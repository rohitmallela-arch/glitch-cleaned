import datetime
import hashlib
import logging
import os
import traceback
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

import requests
import stripe
from flask import Flask, jsonify, make_response, request

from google.cloud import firestore
from google.auth.transport import requests as grequests
from google.oauth2 import id_token as google_id_token

from twilio.request_validator import RequestValidator
from twilio.twiml.messaging_response import MessagingResponse
from twilio.rest import Client as TwilioClient

# -----------------------------------------------------------------------------
# App + logging
# -----------------------------------------------------------------------------
APP_NAME = "glitch-webhook"
app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(APP_NAME)

# -----------------------------------------------------------------------------
# Env helpers
# -----------------------------------------------------------------------------
def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name, default)
    if v is None:
        return None
    return v.strip() if isinstance(v, str) else v

def _bool_env(name: str, default: bool = False) -> bool:
    v = _env(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "t", "yes", "y", "on")

def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def _today_yyyymmdd_utc() -> str:
    return datetime.datetime.utcnow().strftime("%Y%m%d")

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _user_id_from_phone(phone_e164: str) -> str:
    return "u_" + _sha256_hex(phone_e164.strip())

def _ndc_digits(s: str) -> str:
    return "".join(ch for ch in (s or "") if ch.isdigit())

# -----------------------------------------------------------------------------
# Firestore
# -----------------------------------------------------------------------------
db = firestore.Client()

# -----------------------------------------------------------------------------
# Global gates / config
# -----------------------------------------------------------------------------
PAYMENTS_ENABLED = _bool_env("PAYMENTS_ENABLED", False)

STRIPE_PRICE_ID = _env("STRIPE_PRICE_ID")
CHECKOUT_SUCCESS_URL = _env("CHECKOUT_SUCCESS_URL")
CHECKOUT_CANCEL_URL = _env("CHECKOUT_CANCEL_URL")

STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

FDA_SHORTAGE_URL = (_env("FDA_SHORTAGE_URL") or "").strip() or "https://www.accessdata.fda.gov/scripts/drugshortages/api/drugshortages.json"

# -----------------------------------------------------------------------------
# Milestone C.2 — Plan limits & abuse containment (fail-closed)
# -----------------------------------------------------------------------------
FAIL_CLOSED_LIMITS = _bool_env("FAIL_CLOSED_LIMITS", True)

def _require_int_env(name: str) -> int:
    v = os.getenv(name)
    if v is None:
        raise ValueError(f"missing_env:{name}")
    try:
        n = int(str(v).strip())
    except Exception:
        raise ValueError(f"invalid_int_env:{name}={v}")
    if n < 0:
        raise ValueError(f"invalid_int_env:{name}={v}")
    return n

def _limits() -> dict:
    """
    Required env vars (fail-closed when FAIL_CLOSED_LIMITS=true):
      - MAX_WATCHLIST_ITEMS
      - MAX_ALERTS_PER_DAY
      - MAX_ALERTS_PER_NDC_PER_DAY
      - WEEKLY_RECAP_MAX_ITEMS
    """
    return {
        "MAX_WATCHLIST_ITEMS": _require_int_env("MAX_WATCHLIST_ITEMS"),
        "MAX_ALERTS_PER_DAY": _require_int_env("MAX_ALERTS_PER_DAY"),
        "MAX_ALERTS_PER_NDC_PER_DAY": _require_int_env("MAX_ALERTS_PER_NDC_PER_DAY"),
        "WEEKLY_RECAP_MAX_ITEMS": _require_int_env("WEEKLY_RECAP_MAX_ITEMS"),
        "FAIL_CLOSED_LIMITS": FAIL_CLOSED_LIMITS,
    }

def _safe_limits_or_none() -> Optional[dict]:
    try:
        return _limits()
    except Exception as e:
        if FAIL_CLOSED_LIMITS:
            log.error("limits_missing_or_invalid err=%s fail_closed=true", str(e))
            return None
        # Non-fail-closed mode (not recommended) => safe lows
        return {
            "MAX_WATCHLIST_ITEMS": 25,
            "MAX_ALERTS_PER_DAY": 20,
            "MAX_ALERTS_PER_NDC_PER_DAY": 3,
            "WEEKLY_RECAP_MAX_ITEMS": 20,
            "FAIL_CLOSED_LIMITS": False,
        }

def _enforce_watchlist_limit(user_id: str, ndcs: list, source: str) -> None:
    lim = _safe_limits_or_none()
    if lim is None:
        log.info(
            "watchlist_limit_exceeded user_id=%s limit=%s observed=%s source=%s fail_closed=true",
            str(user_id), "missing_env", str(len(ndcs or [])), str(source)
        )
        raise ValueError("limits_missing_or_invalid")

    max_items = lim["MAX_WATCHLIST_ITEMS"]
    observed = len(ndcs or [])
    if observed > max_items:
        log.info(
            "watchlist_limit_exceeded user_id=%s limit=%s observed=%s source=%s fail_closed=true",
            str(user_id), str(max_items), str(observed), str(source)
        )
        raise ValueError("watchlist_limit_exceeded")

def _rate_limit_doc_ref(user_id: str, day: str):
    return db.collection("users").document(user_id).collection("rate_limits").document(day)

def _reserve_send_quota(user_id: str, ndc: Optional[str]):
    """
    Transactionally reserve 1 send quota for (user_id, today).
    Returns (allowed: bool, details: dict).
    Fail-closed: txn errors => NOT allowed.
    """
    lim = _safe_limits_or_none()
    if lim is None:
        return (False, {"reason": "limits_missing_or_invalid"})

    max_total = lim["MAX_ALERTS_PER_DAY"]
    max_ndc = lim["MAX_ALERTS_PER_NDC_PER_DAY"]
    day = _today_yyyymmdd_utc()
    doc_ref = _rate_limit_doc_ref(user_id, day)
    txn = db.transaction()

    import google.cloud.firestore as _fs

    @_fs.transactional
    def _txn(t):
        snap = doc_ref.get(transaction=t)
        data = snap.to_dict() if snap.exists else {}
        total = int(data.get("alerts_sent_total") or 0)

        by_ndc = data.get("alerts_sent_by_ndc") or {}
        ndc_count = None
        if ndc:
            ndc_count = int(by_ndc.get(ndc) or 0)

        if total + 1 > max_total:
            return (False, {
                "day": day,
                "observed_total": total,
                "limit_total": max_total,
                "ndc": ndc or "none",
                "observed_ndc": ndc_count,
                "limit_ndc": max_ndc,
            })

        if ndc and (ndc_count + 1 > max_ndc):
            return (False, {
                "day": day,
                "observed_total": total,
                "limit_total": max_total,
                "ndc": ndc,
                "observed_ndc": ndc_count,
                "limit_ndc": max_ndc,
            })

        new_total = total + 1
        new_by_ndc = dict(by_ndc)
        if ndc:
            new_by_ndc[ndc] = (ndc_count or 0) + 1

        t.set(doc_ref, {
            "day": day,
            "alerts_sent_total": new_total,
            "alerts_sent_by_ndc": new_by_ndc,
            "updated_at": _now_iso(),
        }, merge=True)

        return (True, {
            "day": day,
            "observed_total": total,
            "limit_total": max_total,
            "ndc": ndc or "none",
            "observed_ndc": ndc_count,
            "limit_ndc": max_ndc,
        })

    try:
        return _txn(txn)
    except Exception as e:
        log.info(
            "rate_limit_state_error user_id=%s ndc=%s reason=%s fail_closed=true",
            str(user_id), str(ndc or "none"), str(e)
        )
        return (False, {"reason": "firestore_txn_failed", "err": str(e)})

# -----------------------------------------------------------------------------
# Watchlist parsing (strict, fail-closed)
# -----------------------------------------------------------------------------
def _parse_watchlist_ndcs(raw: Optional[str]) -> List[str]:
    """
    Strict watchlist parsing:
      - Input: comma-separated tokens
      - Each token must be digits-only (fail-closed on invalid token)
      - Output: deterministic de-duplicated list (preserves first-seen order)
    """
    if raw is None:
        return []
    s = str(raw).strip()
    if not s:
        return []

    parts = [p.strip() for p in s.split(",") if p.strip()]
    out: List[str] = []
    seen = set()
    for tok in parts:
        if not tok.isdigit():
            raise ValueError(f"invalid_ndc_token:{tok}")
        if tok not in seen:
            seen.add(tok)
            out.append(tok)
    return out

# -----------------------------------------------------------------------------
# Stripe env checks
# -----------------------------------------------------------------------------
def _require_checkout_env() -> Tuple[bool, List[str]]:
    missing = []
    if not STRIPE_API_KEY:
        missing.append("STRIPE_API_KEY")
    if not STRIPE_PRICE_ID:
        missing.append("STRIPE_PRICE_ID")
    if not CHECKOUT_SUCCESS_URL:
        missing.append("CHECKOUT_SUCCESS_URL")
    if not CHECKOUT_CANCEL_URL:
        missing.append("CHECKOUT_CANCEL_URL")
    return (len(missing) == 0, missing)

# -----------------------------------------------------------------------------
# Operator auth (P0)
# -----------------------------------------------------------------------------
def _request_id() -> str:
    # Prefer upstream request id if present; else deterministic-ish.
    rid = request.headers.get("X-Cloud-Trace-Context", "") or request.headers.get("X-Request-Id", "")
    rid = rid.split("/")[0].strip()
    if rid:
        return rid
    # fallback
    return _sha256_hex(f"{request.path}|{datetime.datetime.utcnow().isoformat()}")[:16]

def require_operator_auth(fn):
    """
    P0: Protect operator endpoints using Google OIDC ID tokens.

    Env:
      - OPERATOR_AUDIENCE: exact audience (typically canonical Cloud Run URL)
      - ALLOWED_OPERATOR_EMAILS: comma-separated allowlist of token 'email' claims
    """
    @wraps(fn)
    def _wrapped(*args, **kwargs):
        rid = _request_id()
        aud = (_env("OPERATOR_AUDIENCE") or "").strip()
        allowed_raw = (_env("ALLOWED_OPERATOR_EMAILS") or "").strip()

        if not aud or not allowed_raw:
            log.info("operator_auth outcome=fail reason=missing_env path=%s request_id=%s", request.path, rid)
            return jsonify({"ok": False, "error": "operator_auth_not_configured"}), 403

        allowed_emails = {x.strip() for x in allowed_raw.split(",") if x.strip()}
        authz = request.headers.get("Authorization", "").strip()
        if not authz.startswith("Bearer "):
            log.info("operator_auth outcome=fail reason=missing_bearer path=%s request_id=%s", request.path, rid)
            return jsonify({"ok": False, "error": "missing_bearer"}), 401

        token = authz.split(" ", 1)[1].strip()
        try:
            req = grequests.Request()
            claims = google_id_token.verify_oauth2_token(token, req, audience=aud)

            iss = str(claims.get("iss") or "")
            if iss not in ("https://accounts.google.com", "accounts.google.com"):
                log.info("operator_auth outcome=fail reason=bad_issuer iss=%s path=%s request_id=%s", iss, request.path, rid)
                return jsonify({"ok": False, "error": "bad_issuer"}), 401

            email = (claims.get("email") or "").strip()
            if not email or email not in allowed_emails:
                log.info("operator_auth outcome=fail reason=email_not_allowed email=%s path=%s request_id=%s", email, request.path, rid)
                return jsonify({"ok": False, "error": "email_not_allowed"}), 403

            log.info("operator_auth outcome=pass email=%s path=%s request_id=%s", email, request.path, rid)
            return fn(*args, **kwargs)

        except Exception as e:
            log.info("operator_auth outcome=fail reason=token_invalid err=%s path=%s request_id=%s", str(e), request.path, rid)
            return jsonify({"ok": False, "error": "token_invalid"}), 401

    return _wrapped

# -----------------------------------------------------------------------------
# Optional/legacy welcome SMS helper
# -----------------------------------------------------------------------------
WELCOME_SMS = (
    "Welcome to Glitch. You will receive shortage alerts for your watchlist.\n\n"
    "Reply STOP to unsubscribe anytime."
)

# Optional/legacy helper:
# Not used in the main activation flow (Stripe webhook sends initial snapshot via _send_message_best_effort).
# Kept for manual/dev onboarding only.
def maybe_send_welcome_sms(phone_e164: str) -> bool:
    if not phone_e164:
        return False

    tw_sid = os.environ.get("TWILIO_ACCOUNT_SID")
    tw_token = os.environ.get("TWILIO_AUTH_TOKEN")
    tw_from = os.environ.get("TWILIO_FROM_NUMBER")
    if not (tw_sid and tw_token and tw_from):
        return False

    try:
        TwilioClient(tw_sid, tw_token).messages.create(
            to=phone_e164,
            from_=tw_from,
            body=WELCOME_SMS,
        )
        return True
    except Exception:
        return False

# -----------------------------------------------------------------------------
# Alert rendering + deterministic name resolution (best-effort, cacheable)
# -----------------------------------------------------------------------------
NAME_RESOLUTION_VERSION = (os.environ.get("NAME_RESOLUTION_VERSION") or "v1").strip() or "v1"

def _shortage_get_by_ndc(ndc_digits: str) -> Tuple[bool, Dict[str, Any]]:
    ndc_digits = (ndc_digits or "").strip()
    if not ndc_digits:
        return False, {}
    try:
        snap = db.collection("drug_shortages").document(ndc_digits).get()
        if snap.exists:
            return True, (snap.to_dict() or {})
    except Exception:
        pass

    # Legacy fallback
    try:
        q = (
            db.collection("drug_shortages")
            .where("ndc_digits", "==", ndc_digits)
            .limit(1)
            .stream()
        )
        doc = next(q, None)
        if doc:
            return True, (doc.to_dict() or {})
    except Exception:
        pass

    return False, {}

def _resolve_name_best_effort(ndc_digits: str, shortage_doc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    ndc_digits = (ndc_digits or "").strip()
    shortage_doc = shortage_doc or {}
    fallback = (shortage_doc.get("name") or shortage_doc.get("drug_name") or "").strip() or "unknown"

    if not ndc_digits:
        return {"name": fallback, "source": "fallback", "version": NAME_RESOLUTION_VERSION}

    cache_coll = f"ndc_name_cache_{NAME_RESOLUTION_VERSION}"
    try:
        snap = db.collection(cache_coll).document(ndc_digits).get()
        if snap.exists:
            d = snap.to_dict() or {}
            nm = (d.get("name") or "").strip()
            if nm:
                return {"name": nm, "source": d.get("source") or "cache", "version": NAME_RESOLUTION_VERSION}
    except Exception:
        pass  # never block

    resolved = fallback
    out = {
        "name": resolved,
        "source": "shortage_doc" if resolved != "unknown" else "fallback",
        "version": NAME_RESOLUTION_VERSION,
    }

    try:
        db.collection(cache_coll).document(ndc_digits).set(
            {
                "ndc_digits": ndc_digits,
                "name": resolved,
                "source": out["source"],
                "version": NAME_RESOLUTION_VERSION,
                "updated_at": _now_iso(),
            },
            merge=True,
        )
    except Exception:
        pass

    return out

def _render_instant_alert(ndc_digits: str, shortage_doc: Dict[str, Any], event: Dict[str, Any]) -> str:
    ndc_digits = (ndc_digits or "").strip()
    status = (shortage_doc.get("status") or shortage_doc.get("current_status") or "unknown").strip()
    prev_status = (event.get("prev_status") or "").strip()
    reason = (event.get("reason") or "status_change").strip()
    resolved = _resolve_name_best_effort(ndc_digits, shortage_doc)
    name = resolved.get("name") or "unknown"

    headline = "🚨 GLITCH ALERT"
    line1 = f"Drug: {name}"
    line2 = f"NDC: {ndc_digits}" if ndc_digits else "NDC: unknown"
    line3 = f"Status: {prev_status} → {status}" if prev_status else f"Status: {status}"
    footer = "\n\nReply STOP to unsubscribe.\n— Glitch"
    return "\n".join([headline, "━━━━━━━━━━━━━━━━━━━━", line1, line2, line3, f"Reason: {reason}"]) + footer

def _week_key_utc(dt: Optional[datetime.datetime] = None) -> str:
    dt = dt or datetime.datetime.utcnow()
    iso = dt.isocalendar()
    return f"{iso.year}-W{int(iso.week):02d}"

def _render_weekly_summary(artifact: Dict[str, Any]) -> str:
    observed = int(artifact.get("observed") or 0)
    body_lines = artifact.get("lines") or []
    if not isinstance(body_lines, list):
        body_lines = []
    body = "\n".join(body_lines) if body_lines else "No new shortages this week."

    return (
        "📊 GLITCH WEEKLY SUMMARY\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Did anything important happen?  {'Yes' if observed else 'No'}\n"
        f"Did I miss anything?          {'No (you are covered)' if observed >= 0 else 'Unknown'}\n"
        f"Am I okay right now?          {'Monitoring is ACTIVE' if artifact.get('monitoring_active') else 'Unknown'}\n\n"
        f"Total New Alerts: {observed}\n"
        f"{body}\n\n"
        "✅ Supply chain monitoring is ACTIVE.\n"
        "— Glitch"
    )

def _write_weekly_summary_artifact(week_key: str, observed: int, lines_list: List[str], max_items: int) -> Dict[str, Any]:
    artifact = {
        "week_key": week_key,
        "observed": int(observed),
        "limit": int(max_items),
        "lines": list(lines_list),
        "monitoring_active": True,
        "generated_at": _now_iso(),
    }
    try:
        db.collection("weekly_summaries").document(week_key).set(artifact, merge=True)
    except Exception:
        pass
    return artifact

def _compose_initial_snapshot(user_id: str, ndcs: List[str]) -> str:
    lim = _safe_limits_or_none()
    cap = 20
    if lim is not None:
        cap = min(50, max(5, int(lim.get("WEEKLY_RECAP_MAX_ITEMS") or 20)))

    lines = ["Glitch — Initial snapshot", f"User: {user_id}", ""]
    if not ndcs:
        lines.append("No watchlisted NDCs.")
        return "\n".join(lines)

    shown = 0
    for ndc in ndcs:
        if shown >= cap:
            break
        exists, doc = _shortage_get_by_ndc(ndc)
        status = (doc.get("status") or doc.get("current_status") or "unknown").strip() if exists else "unknown"
        resolved = _resolve_name_best_effort(ndc, doc if exists else {})
        name = (resolved.get("name") or "unknown").strip()
        lines.append(f"- {name} ({ndc}): {status}")
        shown += 1

    if len(ndcs) > shown:
        lines.append(f"...and {len(ndcs) - shown} more.")

    return "\n".join(lines)

# -----------------------------------------------------------------------------
# Central notification send (billing + eligibility + rate limits)
# -----------------------------------------------------------------------------
def _send_message_best_effort(user_doc: dict, text: str, ndc: Optional[str] = None) -> bool:
    """
    Gates (fail-closed):
      1) users.status must be "active"
      2) PAYMENTS_ENABLED must be true (global operator kill switch)
      3) Rate limits (Milestone C.2):
         - MAX_ALERTS_PER_DAY (per user per day)
         - MAX_ALERTS_PER_NDC_PER_DAY (if ndc provided)
    """
    user_doc = user_doc or {}
    user_id = (user_doc.get("user_id") or "").strip()
    status = user_doc.get("status")

    # Removed dead fallback fetch: callers MUST pass status (defensive, reduces reads).
    if status != "active":
        log.info("notify_skip_ineligible user_id=%s status=%s", str(user_id), str(status))
        return False

    if not _bool_env("PAYMENTS_ENABLED", False):
        log.info("notify_skip_billing_disabled user_id=%s payments_enabled=false", str(user_id))
        return False

    if not user_id:
        log.info(
            "notify_skip_over_limit user_id=%s limit_total=%s observed_total=%s limit_ndc=%s observed_ndc=%s ndc=%s channel=%s fail_closed=true",
            str(user_id), "unknown", "unknown", "unknown", "unknown", str(ndc or "none"), "none"
        )
        return False

    allowed, details = _reserve_send_quota(user_id, ndc)
    if not allowed:
        log.info(
            "notify_skip_over_limit user_id=%s limit_total=%s observed_total=%s limit_ndc=%s observed_ndc=%s ndc=%s channel=%s fail_closed=true",
            str(user_id),
            str(details.get("limit_total", "unknown")),
            str(details.get("observed_total", "unknown")),
            str(details.get("limit_ndc", "unknown")),
            str(details.get("observed_ndc", "unknown")),
            str(details.get("ndc", ndc or "none")),
            "none",
        )
        return False

    attempted_any = False

    # Telegram
    tg_token = _env("TELEGRAM_BOT_TOKEN")
    tg_chat = user_doc.get("telegram_chat_id")
    if tg_token and tg_chat:
        attempted_any = True
        try:
            resp = requests.post(
                f"https://api.telegram.org/bot{tg_token}/sendMessage",
                json={"chat_id": tg_chat, "text": text},
                timeout=10,
            )
            log.info(
                "telegram_send_result user_id=%s chat_id=%s status=%s body=%s",
                str(user_id),
                str(tg_chat),
                str(getattr(resp, "status_code", "na")),
                (resp.text[:200] if hasattr(resp, "text") else "na"),
            )
        except Exception as e:
            log.error("telegram_send_failed user_id=%s err=%s", str(user_id), str(e))

    # Twilio
    tw_sid = _env("TWILIO_ACCOUNT_SID")
    tw_token = _env("TWILIO_AUTH_TOKEN")
    tw_from = _env("TWILIO_FROM_NUMBER")
    phone = user_doc.get("phone_e164")
    if tw_sid and tw_token and tw_from and phone:
        attempted_any = True
        try:
            TwilioClient(tw_sid, tw_token).messages.create(
                to=phone,
                from_=tw_from,
                body=text,
            )
        except Exception as e:
            log.error("twilio_send_failed user_id=%s err=%s", str(user_id), str(e))

    return attempted_any

# -----------------------------------------------------------------------------
# User + watchlist upsert (activation)
# -----------------------------------------------------------------------------
def _upsert_user_and_watchlist(phone_e164: str, email: Optional[str], ndcs: List[str], etype: str) -> str:
    user_id = _user_id_from_phone(phone_e164)
    user_ref = db.collection("users").document(user_id)
    existing = user_ref.get().to_dict() or {}

    merged = dict(existing)
    merged.update({
        "user_id": user_id,
        "phone_e164": phone_e164,
        "email": email or existing.get("email"),
        "status": "active",
        "stripe_last_event": etype,
        "updated_at": _now_iso(),
    })
    if "created_at" not in merged:
        merged["created_at"] = _now_iso()

    user_ref.set(merged, merge=True)

    for ndc in ndcs:
        user_ref.collection("watchlist_items").document(ndc).set({
            "ndc_digits": ndc,
            "created_at": _now_iso(),
        }, merge=True)

        db.collection("ndc_watchers").document(ndc).collection("watchers").document(user_id).set({
            "user_id": user_id,
            "ndc_digits": ndc,
            "created_at": _now_iso(),
        }, merge=True)

    return user_id

# -----------------------------------------------------------------------------
# UI CORS (Milestone E.0) — allow browser embedding for /ui/* only
# -----------------------------------------------------------------------------
_UI_CORS_ALLOW_ORIGIN = os.environ.get("UI_CORS_ALLOW_ORIGIN") or "*"

def _is_ui_path(path: str) -> bool:
    return (path or "").startswith("/ui/")

@app.before_request
def _ui_cors_preflight():
    if _is_ui_path(request.path) and request.method == "OPTIONS":
        resp = make_response("", 204)
        resp.headers["Access-Control-Allow-Origin"] = _UI_CORS_ALLOW_ORIGIN
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        resp.headers["Access-Control-Max-Age"] = "3600"
        return resp
    return None

@app.after_request
def _ui_cors_headers(resp):
    if _is_ui_path(request.path):
        resp.headers["Access-Control-Allow-Origin"] = _UI_CORS_ALLOW_ORIGIN
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def root():
    return jsonify({"ok": True, "service": APP_NAME}), 200

# Health checks:
# We expose BOTH /healthz and /healthz/ because different monitors/integrations
# may normalize trailing slashes differently. Keep both to avoid false 404s.
@app.route("/healthz", methods=["GET"])
@app.route("/healthz/", methods=["GET"])
def healthz():
    return jsonify({"ok": True}), 200

@app.route("/ui/status", methods=["GET"])
@app.route("/ui/status/", methods=["GET"])
def ui_status():
    k_service = os.environ.get("K_SERVICE")
    k_revision = os.environ.get("K_REVISION")

    def _int(v, default=None):
        try:
            return int(str(v).strip())
        except Exception:
            return default

    limits = {
        "MAX_WATCHLIST_ITEMS": _int(os.environ.get("MAX_WATCHLIST_ITEMS")),
        "MAX_ALERTS_PER_DAY": _int(os.environ.get("MAX_ALERTS_PER_DAY")),
        "MAX_ALERTS_PER_NDC_PER_DAY": _int(os.environ.get("MAX_ALERTS_PER_NDC_PER_DAY")),
        "WEEKLY_RECAP_MAX_ITEMS": _int(os.environ.get("WEEKLY_RECAP_MAX_ITEMS")),
        "FAIL_CLOSED_LIMITS": _bool_env("FAIL_CLOSED_LIMITS", True),
    }

    payload = {
        "ok": True,
        "service": APP_NAME,
        "cloud_run": {"K_SERVICE": k_service, "K_REVISION": k_revision},
        "now_utc": _now_iso(),
        "health": {"canonical_path": "/healthz/", "note": "Use /healthz/ (trailing slash) for monitoring."},
        "billing": {"PAYMENTS_ENABLED": _bool_env("PAYMENTS_ENABLED", False)},
        "limits": limits,
        "roll_marker_present": bool(os.environ.get("ROLL_MARKER")),
        "host": {
            "request_host": request.host,
            "canonical_external_hostname": "glitch-webhook-129120132071.us-central1.run.app",
            "cloud_run_default_hostname": "glitch-webhook-dmsse4fh6q-uc.a.run.app",
            "canonical_note": "Use the canonical *.run.app hostname for Stripe/Carrd/Scheduler.",
        },
    }
    return jsonify(payload), 200

@app.route("/ui/user/status", methods=["POST"])
@app.route("/ui/user/status/", methods=["POST"])
def ui_user_status():
    payload = request.get_json(force=True, silent=True) or {}
    phone = (payload.get("phone_e164") or "").strip()
    if not phone or not phone.startswith("+"):
        return jsonify({"ok": False, "error": "invalid_phone"}), 400

    user_id = _user_id_from_phone(phone)

    def _int(v, default=None):
        try:
            return int(str(v).strip())
        except Exception:
            return default

    limits = {
        "MAX_WATCHLIST_ITEMS": _int(os.environ.get("MAX_WATCHLIST_ITEMS")),
        "MAX_ALERTS_PER_DAY": _int(os.environ.get("MAX_ALERTS_PER_DAY")),
        "MAX_ALERTS_PER_NDC_PER_DAY": _int(os.environ.get("MAX_ALERTS_PER_NDC_PER_DAY")),
        "WEEKLY_RECAP_MAX_ITEMS": _int(os.environ.get("WEEKLY_RECAP_MAX_ITEMS")),
        "FAIL_CLOSED_LIMITS": _bool_env("FAIL_CLOSED_LIMITS", True),
    }

    try:
        user_ref = db.collection("users").document(user_id)
        snap = user_ref.get()
        user_doc = (snap.to_dict() or {}) if snap.exists else {}

        status = user_doc.get("status")
        created_at = user_doc.get("created_at")
        updated_at = user_doc.get("updated_at")

        preview = []
        count = 0
        for i, doc in enumerate(user_ref.collection("watchlist_items").stream()):
            count += 1
            if len(preview) < 10:
                d = doc.to_dict() or {}
                ndc = (d.get("ndc_digits") or doc.id or "").strip()
                if ndc:
                    preview.append(ndc)
            if i >= 199:
                break

    except Exception as e:
        log.error("ui_user_status_firestore_error user_id=%s err=%s fail_closed=true", str(user_id), str(e))
        return jsonify({"ok": False, "error": "unavailable"}), 503

    out = {
        "ok": True,
        "now_utc": _now_iso(),
        "user": {
            "user_id": user_id,
            "phone_e164": phone,
            "status": status or ("missing" if not user_doc else "unknown"),
            "created_at": created_at,
            "updated_at": updated_at,
        },
        "watchlist": {"count": count, "items_preview": preview, "preview_cap": 10, "scan_cap": 200},
        "limits": limits,
        "notes": [
            "If status is not active, notifications are skipped server-side.",
            "This endpoint is read-only transparency; limits and enforcement occur server-side.",
        ],
    }
    return jsonify(out), 200

@app.route("/ui/user/diagnostics", methods=["POST"])
@app.route("/ui/user/diagnostics/", methods=["POST"])
def ui_user_diagnostics():
    payload = request.get_json(force=True, silent=True) or {}
    phone = (payload.get("phone_e164") or "").strip()
    ndc_raw = (payload.get("ndc_digits") or "").strip()

    if not phone or not phone.startswith("+"):
        return jsonify({"ok": False, "error": "invalid_phone"}), 400

    ndc = ""
    if ndc_raw:
        ndc = _ndc_digits(ndc_raw)
        if not ndc:
            return jsonify({"ok": False, "error": "invalid_ndc"}), 400

    user_id = _user_id_from_phone(phone)
    now_utc = _now_iso()
    day = _today_yyyymmdd_utc()

    payments_enabled = _bool_env("PAYMENTS_ENABLED", False)
    max_total = os.environ.get("MAX_ALERTS_PER_DAY")
    max_ndc = os.environ.get("MAX_ALERTS_PER_NDC_PER_DAY")
    fail_closed_limits = _bool_env("FAIL_CLOSED_LIMITS", True)

    def _int(v):
        try:
            return int(str(v).strip())
        except Exception:
            return None

    max_total_i = _int(max_total)
    max_ndc_i = _int(max_ndc)

    try:
        user_ref = db.collection("users").document(user_id)
        snap = user_ref.get()
        user_exists = bool(snap.exists)
        user_doc = (snap.to_dict() or {}) if snap.exists else {}

        status = (user_doc.get("status") or "").strip()
        created_at = user_doc.get("created_at")
        updated_at = user_doc.get("updated_at")
        user_active = (status == "active")

        ndc_in_watchlist = None
        watchlist_count = 0
        if ndc:
            ndc_in_watchlist = False

        for i, doc in enumerate(user_ref.collection("watchlist_items").stream()):
            watchlist_count += 1
            if ndc and not ndc_in_watchlist:
                d = doc.to_dict() or {}
                w = (d.get("ndc_digits") or doc.id or "").strip()
                if w == ndc:
                    ndc_in_watchlist = True
            if i >= 199:
                break

        rl_ref = _rate_limit_doc_ref(user_id, day)
        rl_snap = rl_ref.get()
        rl_doc_exists = bool(rl_snap.exists)
        rl = (rl_snap.to_dict() or {}) if rl_snap.exists else {}

        alerts_sent_today = int(rl.get("alerts_sent_total") or 0)
        alerts_sent_for_ndc_today = None
        if ndc:
            by_ndc = rl.get("alerts_sent_by_ndc") or {}
            alerts_sent_for_ndc_today = int(by_ndc.get(ndc) or 0)

        shortage_exists = None
        shortage_status = None
        shortage_doc_id = None
        if ndc:
            shortage_exists = False
            # deterministic: prefer canonical doc id, then fallback query
            snap2 = db.collection("drug_shortages").document(ndc).get()
            if snap2.exists:
                shortage_exists = True
                shortage_doc_id = ndc
                d2 = snap2.to_dict() or {}
                shortage_status = d2.get("status") or d2.get("current_status") or "unknown"
            else:
                q = (
                    db.collection("drug_shortages")
                    .where("ndc_digits", "==", ndc)
                    .limit(1)
                    .stream()
                )
                doc2 = next(q, None)
                if doc2:
                    shortage_exists = True
                    shortage_doc_id = doc2.id
                    d2 = doc2.to_dict() or {}
                    shortage_status = d2.get("status") or d2.get("current_status") or "unknown"

    except Exception as e:
        log.error("ui_user_diagnostics_firestore_error user_id=%s err=%s fail_closed=true", str(user_id), str(e))
        return jsonify({"ok": False, "error": "unavailable"}), 503

    checks = []

    def _add(code: str, passed: bool, detail: str):
        checks.append({"code": code, "pass": bool(passed), "detail": detail})

    eligible = True
    primary_code = "ELIGIBLE"
    primary_human = "User is active and limits not exceeded."

    _add("USER_EXISTS", user_exists, "User document found." if user_exists else "User document not found.")
    if not user_exists:
        eligible = False
        primary_code = "USER_EXISTS"
        primary_human = "No user record exists for this phone. Alerts are skipped."

    _add("USER_ACTIVE", user_active, "User status is active." if user_active else f"User status is '{status or 'missing'}'.")
    if eligible and not user_active:
        eligible = False
        primary_code = "USER_ACTIVE"
        primary_human = "User is not active. Alerts are skipped."

    _add("PAYMENTS_ENABLED", payments_enabled, "Payments are enabled." if payments_enabled else "Payments are disabled.")
    if eligible and not payments_enabled:
        eligible = False
        primary_code = "PAYMENTS_ENABLED"
        primary_human = "Billing is disabled. Alerts are skipped."

    if ndc:
        _add("WATCHLIST_MATCH", bool(ndc_in_watchlist), "NDC is in watchlist." if ndc_in_watchlist else "NDC is not in watchlist.")
        if eligible and not ndc_in_watchlist:
            eligible = False
            primary_code = "WATCHLIST_MATCH"
            primary_human = "This NDC is not in the user's watchlist. Alerts would not fire."

    if max_total_i is None:
        _add("DAILY_LIMIT", True, "Daily limit env missing; enforcement may fail-closed server-side.")
    else:
        _add("DAILY_LIMIT", (alerts_sent_today < int(max_total_i)), f"{alerts_sent_today}/{int(max_total_i)} used today.")
        if eligible and alerts_sent_today >= int(max_total_i):
            eligible = False
            primary_code = "DAILY_LIMIT"
            primary_human = "Daily alert limit exceeded. Alerts are skipped for today."

    if ndc:
        if max_ndc_i is None:
            _add("PER_NDC_LIMIT", True, "Per-NDC limit env missing; enforcement may fail-closed server-side.")
        else:
            obs = int(alerts_sent_for_ndc_today or 0)
            _add("PER_NDC_LIMIT", (obs < int(max_ndc_i)), f"{obs}/{int(max_ndc_i)} used today for this NDC.")
            if eligible and obs >= int(max_ndc_i):
                eligible = False
                primary_code = "PER_NDC_LIMIT"
                primary_human = "Per-NDC alert limit exceeded. Alerts are skipped for this NDC today."

    if ndc:
        _add("NO_MATCHING_SHORTAGE", bool(shortage_exists), "Matching shortage record found." if shortage_exists else "No matching shortage record found.")
        if eligible and not shortage_exists:
            eligible = False
            primary_code = "NO_MATCHING_SHORTAGE"
            primary_human = "No current shortage record matches this NDC. Alerts would not fire."

    out = {
        "ok": True,
        "phone_e164": phone,
        "ndc_digits": ndc or None,
        "now_utc": now_utc,
        "day_key_utc": day,
        "user": {
            "user_id": user_id,
            "exists": user_exists,
            "active": user_active,
            "status": status or ("missing" if not user_exists else "unknown"),
            "created_at": created_at,
            "updated_at": updated_at,
            "watchlist_count": watchlist_count,
            "ndc_in_watchlist": ndc_in_watchlist,
        },
        "limits": {
            "payments_enabled": payments_enabled,
            "max_alerts_per_day": max_total_i,
            "max_alerts_per_ndc_per_day": max_ndc_i,
            "fail_closed_limits": fail_closed_limits,
        },
        "shortage": {
            "exists": shortage_exists,
            "status": shortage_status,
            "doc_id": shortage_doc_id,
        },
        "rate_limits": {
            "doc_exists": rl_doc_exists,
            "alerts_sent_today": alerts_sent_today,
            "alerts_sent_for_ndc_today": alerts_sent_for_ndc_today,
        },
        "decision": {
            "eligible_to_alert_now": eligible,
            "primary_reason_code": primary_code,
            "primary_reason_human": primary_human,
        },
        "checks": checks,
        "notes": [
            "This endpoint explains eligibility gates (user/billing/watchlist/limits).",
            "Rate limit doc missing is treated as 0 used; Firestore errors fail-closed (503).",
        ],
    }
    return jsonify(out), 200

@app.route("/create_checkout_session", methods=["POST"])
def create_checkout_session():
    ok, missing = _require_checkout_env()
    if not ok:
        return jsonify({"error": "stripe_checkout_missing_env", "missing": missing}), 500

    payload = request.get_json(force=True, silent=True) or {}
    phone = (payload.get("phone_e164") or "").strip()
    email = (payload.get("email") or "").strip() or None

    if not phone.startswith("+"):
        return jsonify({"error": "invalid_phone"}), 400

    try:
        ndcs = _parse_watchlist_ndcs(payload.get("watchlist_ndcs"))
        _enforce_watchlist_limit(_user_id_from_phone(phone), ndcs, "checkout_session_create")
    except Exception as e:
        log.info(
            "watchlist_parse_failed user_id=%s reason=%s source=%s fail_closed=true",
            str(_user_id_from_phone(phone)), str(e), "checkout_session_create"
        )
        return jsonify({"error": "watchlist_invalid_or_over_limit"}), 400

    stripe.api_key = STRIPE_API_KEY

    session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        success_url=CHECKOUT_SUCCESS_URL,
        cancel_url=CHECKOUT_CANCEL_URL,
        client_reference_id=_user_id_from_phone(phone),
        customer_email=email,
        metadata={
            "phone_e164": phone,
            "watchlist_ndcs": ",".join(ndcs),
            "email": email or "",
        },
    )

    return jsonify({"url": session.url}), 200

@app.route("/stripe_webhook", methods=["POST"])
def stripe_webhook():
    if not PAYMENTS_ENABLED:
        return "stripe_not_configured", 501

    if not STRIPE_API_KEY or not STRIPE_WEBHOOK_SECRET:
        return jsonify({"error": "stripe_webhook_missing_env"}), 500

    stripe.api_key = STRIPE_API_KEY

    payload = request.data
    sig_header = request.headers.get("Stripe-Signature", "")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=STRIPE_WEBHOOK_SECRET,
        )
    except Exception as e:
        log.error("stripe_signature_verification_failed err=%s", str(e))
        log.error(traceback.format_exc())
        return jsonify({"error": "signature_verification_failed"}), 400

    try:
        event_id = event.get("id") or ""
        etype = event.get("type") or ""
        created = event.get("created")
        obj = (event.get("data") or {}).get("object") or {}

        # Idempotency
        if event_id:
            idem_ref = db.collection("processed_stripe_events").document(event_id)
            if idem_ref.get().exists:
                log.info("stripe_webhook_idempotent_skip event_id=%s type=%s", event_id, etype)
                return jsonify({"ok": True, "type": etype, "idempotent": True}), 200
            idem_ref.set({
                "event_id": event_id,
                "event_type": etype,
                "stripe_created": created,
                "received_at": _now_iso(),
            }, merge=True)

        user_id = (obj.get("client_reference_id") or "").strip()
        customer = obj.get("customer")
        subscription = obj.get("subscription")

        log.info(
            "stripe_webhook_received event_id=%s type=%s user_id=%s customer=%s subscription=%s",
            event_id, etype, user_id, str(customer), str(subscription)
        )

        def _set_user_status(uid: str, status: str, reason_type: str):
            if not uid:
                return
            db.collection("users").document(uid).set({
                "status": status,
                "billing_disabled_at": _now_iso(),
                "stripe_last_event": reason_type,
                "stripe_last_event_id": event_id,
                "updated_at": _now_iso(),
            }, merge=True)

        if etype == "checkout.session.completed":
            md = obj.get("metadata") or {}
            phone = (md.get("phone_e164") or "").strip()
            email = (md.get("email") or obj.get("customer_email"))
            ndcs = _parse_watchlist_ndcs(md.get("watchlist_ndcs"))

            _enforce_watchlist_limit(user_id or _user_id_from_phone(phone), ndcs, "stripe_webhook_activation")
            if not phone:
                raise ValueError("missing metadata.phone_e164")

            user_id = _upsert_user_and_watchlist(phone, email, ndcs, etype)

            user_ref = db.collection("users").document(user_id)
            user_doc = user_ref.get().to_dict() or {}
            user_doc = {**user_doc, "user_id": user_id}

            if not user_doc.get("initial_snapshot_sent_at"):
                msg = _compose_initial_snapshot(user_id, ndcs)
                _send_message_best_effort(user_doc, msg, ndc=None)
                user_ref.set({"initial_snapshot_sent_at": _now_iso()}, merge=True)

            user_ref.set({
                "status": "active",
                "stripe_last_event": etype,
                "stripe_last_event_id": event_id,
                "updated_at": _now_iso(),
            }, merge=True)

        elif etype == "invoice.payment_failed":
            uid = user_id
            sub_id = obj.get("subscription")
            try:
                if (not uid) and sub_id:
                    sub = stripe.Subscription.retrieve(sub_id)
                    smd = (sub.get("metadata") or {})
                    uid = (smd.get("user_id") or smd.get("client_reference_id") or "").strip()
            except Exception as e:
                log.error("stripe_subscription_lookup_failed sub=%s err=%s", str(sub_id), str(e))

            _set_user_status(uid, "suspended", etype)

        elif etype == "customer.subscription.deleted":
            uid = user_id
            try:
                smd = (obj.get("metadata") or {})
                if not uid:
                    uid = (smd.get("user_id") or smd.get("client_reference_id") or "").strip()
            except Exception:
                pass

            _set_user_status(uid, "canceled", etype)

        return jsonify({"ok": True, "type": etype}), 200

    except Exception as e:
        log.error("stripe_webhook_handler_crashed err=%s", str(e))
        log.error(traceback.format_exc())
        return jsonify({"error": "webhook_handler_error"}), 500

# -----------------------------------------------------------------------------
# Twilio inbound (P1)
# -----------------------------------------------------------------------------
@app.route("/twilio/inbound", methods=["POST"])
def twilio_inbound():
    """
    P1: inbound SMS activation (YES).
    - Verifies X-Twilio-Signature using TWILIO_AUTH_TOKEN (fail-closed)
    - Idempotently sets users/{user_id}.activated_at when Body == YES
    - Returns TwiML
    - Emits exactly one structured log line:
        inbound_sms request_id=... from=... body_norm=... sig_valid=... action=...
    """
    rid = _request_id()
    tw_token = _env("TWILIO_AUTH_TOKEN")
    if not tw_token:
        log.info("inbound_sms request_id=%s from=%s body_norm=%s sig_valid=%s action=%s",
                 rid, "unknown", "unknown", "false", "missing_env")
        # do not leak details; Twilio will retry but we prefer fail-closed
        resp = MessagingResponse()
        resp.message("Glitch is temporarily unavailable. Please try again later.")
        return str(resp), 200, {"Content-Type": "application/xml"}

    form = request.form.to_dict(flat=True) if request.form else {}
    from_phone = (form.get("From") or "").strip()
    body = (form.get("Body") or "").strip()
    body_norm = body.upper().strip()

    # Reconstruct the URL Twilio signed (Cloud Run behind proxy)
    proto = (request.headers.get("X-Forwarded-Proto") or request.scheme or "https").split(",")[0].strip()
    host = (request.headers.get("X-Forwarded-Host") or request.headers.get("Host") or request.host).split(",")[0].strip()
    url = f"{proto}://{host}{request.path}"

    sig = request.headers.get("X-Twilio-Signature") or request.headers.get("X-Twilio-Signature".lower()) or ""
    validator = RequestValidator(tw_token)
    sig_valid = False
    try:
        sig_valid = validator.validate(url, form, sig)
    except Exception:
        sig_valid = False

    action = "ignored"
    try:
        if not sig_valid:
            action = "sig_invalid"
        elif not from_phone:
            action = "missing_from"
        else:
            user_id = _user_id_from_phone(from_phone)
            user_ref = db.collection("users").document(user_id)
            snap = user_ref.get()
            if not snap.exists:
                action = "user_not_found"
            else:
                u = snap.to_dict() or {}
                # Optional safety: ensure phone matches
                if (u.get("phone_e164") or "").strip() and (u.get("phone_e164") or "").strip() != from_phone:
                    action = "phone_mismatch"
                else:
                    if body_norm == "YES":
                        # idempotent activation
                        if u.get("activated_at"):
                            action = "already_activated"
                        else:
                            user_ref.set({"activated_at": _now_iso(), "updated_at": _now_iso()}, merge=True)
                            action = "activated_yes"
                    elif body_norm == "STOP":
                        action = "stop_received"
                    else:
                        action = "non_yes"
    except Exception:
        action = "exception"

    log.info(
        "inbound_sms request_id=%s from=%s body_norm=%s sig_valid=%s action=%s",
        rid, from_phone or "unknown", body_norm or "empty", str(bool(sig_valid)).lower(), action
    )

    resp = MessagingResponse()
    if action == "activated_yes":
        resp.message("✅ Glitch activated. You’ll only get alerts when shortage status changes for your watchlist.")
    elif action == "already_activated":
        resp.message("✅ Glitch is already active for your number.")
    elif action == "user_not_found":
        resp.message("We couldn’t find your Glitch account. Please sign up first.")
    elif action == "sig_invalid":
        resp.message("Request not authorized.")
    else:
        resp.message("OK.")

    return str(resp), 200, {"Content-Type": "application/xml"}

# -----------------------------------------------------------------------------
# Operator endpoints (protected)
# -----------------------------------------------------------------------------
@app.route("/shortage_poll_run", methods=["POST"])
@require_operator_auth
def shortage_poll_run():
    lim = _safe_limits_or_none()
    if lim is None:
        return jsonify({"error": "limits_missing_or_invalid"}), 500

    try:
        resp = requests.get(FDA_SHORTAGE_URL, timeout=20)
        if getattr(resp, "status_code", 500) != 200:
            return jsonify({"error": "fda_fetch_failed", "status": getattr(resp, "status_code", "na")}), 502
        payload = resp.json()
    except Exception as e:
        log.error("shortage_poll_fetch_failed err=%s", str(e))
        return jsonify({"error": "fda_fetch_exception"}), 502

    items = payload.get("results") if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        return jsonify({"error": "fda_payload_unexpected"}), 502

    processed = 0
    changed = 0
    alerted_attempted = 0
    now = datetime.datetime.utcnow()

    for it in items:
        if not isinstance(it, dict):
            continue

        ndc_raw = (it.get("ndc") or it.get("ndc_digits") or it.get("ndcNumber") or "").strip()
        ndc = _ndc_digits(ndc_raw)
        if not ndc:
            continue

        name = (it.get("drug_name") or it.get("name") or it.get("product") or "").strip()
        status = (it.get("status") or it.get("current_status") or it.get("shortage_status") or "").strip() or "unknown"
        last_updated = it.get("last_updated") or it.get("update_date") or None

        prev_exists, prev = _shortage_get_by_ndc(ndc)
        prev_status = (prev.get("status") or prev.get("current_status") or "").strip() if prev_exists else ""

        doc = {
            "ndc_digits": ndc,
            "name": name or prev.get("name") or prev.get("drug_name") or "",
            "status": status,
            "last_updated": last_updated or now,
            "updated_at": _now_iso(),
            "source": "fda_shortages_api",
        }

        try:
            db.collection("drug_shortages").document(ndc).set(doc, merge=True)
        except Exception as e:
            log.error("shortage_poll_upsert_failed ndc=%s err=%s", str(ndc), str(e))
            continue

        processed += 1

        if prev_status and status and prev_status != status:
            changed += 1
            event = {
                "event_type": "status_change",
                "ndc_digits": ndc,
                "prev_status": prev_status,
                "status": status,
                "reason": "status_change",
                "at": _now_iso(),
            }
            msg = _render_instant_alert(ndc, doc, event)

            try:
                watchers_ref = db.collection("ndc_watchers").document(ndc).collection("watchers")
                for w in watchers_ref.stream():
                    wd = w.to_dict() or {}
                    user_id = (wd.get("user_id") or w.id or "").strip()
                    if not user_id:
                        continue
                    try:
                        usnap = db.collection("users").document(user_id).get()
                        if not usnap.exists:
                            continue
                        u = usnap.to_dict() or {}
                        u = {**u, "user_id": user_id}
                        _send_message_best_effort(u, msg, ndc=ndc)
                        alerted_attempted += 1
                    except Exception:
                        continue
            except Exception as e:
                log.error("shortage_poll_watchers_failed ndc=%s err=%s", str(ndc), str(e))

    return jsonify({"ok": True, "processed": processed, "changed": changed, "alerted_attempted": alerted_attempted}), 200

@app.route("/weekly_recap_run", methods=["POST"])
@require_operator_auth
def weekly_recap_run():
    lim = _safe_limits_or_none()
    if lim is None:
        return jsonify({"error": "limits_missing_or_invalid"}), 500

    max_items = int(lim.get("WEEKLY_RECAP_MAX_ITEMS") or 0)
    if max_items <= 0:
        return jsonify({"error": "weekly_recap_invalid_limit"}), 500

    from datetime import datetime as _dt, timedelta as _td
    seven_days_ago = _dt.utcnow() - _td(days=7)

    try:
        # Bounded read (quick win): read only slightly more than we might render
        q = (
            db.collection("drug_shortages")
            .where("last_updated", ">=", seven_days_ago)
            .limit(max_items + 100)
            .stream()
        )

        lines_list: List[str] = []
        for doc in q:
            d = doc.to_dict() or {}
            ndc = (d.get("ndc_digits") or doc.id or "").strip()
            resolved = _resolve_name_best_effort(ndc, d)
            name = (resolved.get("name") or "unknown").strip()
            if ndc:
                lines_list.append(f"• {name} ({ndc})")
            else:
                lines_list.append(f"• {name}")

    except Exception as e:
        log.error("weekly_recap_query_failed err=%s", str(e))
        return jsonify({"error": "weekly_recap_query_failed"}), 500

    observed = len(lines_list)
    if observed > max_items:
        log.info("weekly_recap_truncated observed=%s limit=%s", str(observed), str(max_items))
        lines_list = lines_list[:max_items]

    week_key = _week_key_utc()
    artifact = _write_weekly_summary_artifact(week_key, observed, lines_list, max_items)
    msg = _render_weekly_summary(artifact)

    sent_attempted = 0
    skipped = 0

    for snap in db.collection("users").stream():
        u = snap.to_dict() or {}
        user_id = snap.id
        u = {**u, "user_id": user_id}
        try:
            _send_message_best_effort(u, msg, ndc=None)
            if u.get("status") == "active":
                sent_attempted += 1
        except Exception:
            skipped += 1

    return jsonify({
        "ok": True,
        "week_key": week_key,
        "observed": observed,
        "limit": max_items,
        "sent_attempted": sent_attempted,
        "skipped": skipped
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
