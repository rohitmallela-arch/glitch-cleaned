import os
import hashlib
from datetime import datetime, timezone
from google.cloud import firestore
import requests

PROJECT_ID = os.environ["PROJECT_ID"]
PHONE_E164 = os.environ["PHONE_E164"]
WATCHLIST_NDCS = os.environ.get("WATCHLIST_NDCS", "")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()

WELCOME_SMS = (
    "Glitch is live ✅ You’ll only get a text when the FDA shortage status changes "
    "for a drug you’re tracking — no daily noise."
)

def user_id_from_phone(phone: str) -> str:
    # stable deterministic id; avoids PII in doc id
    return "u_" + hashlib.sha1(phone.encode("utf-8")).hexdigest()

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def maybe_send_telegram_welcome(ref, doc: dict) -> dict:
    """
    Idempotent Telegram welcome:
      - Requires TELEGRAM_BOT_TOKEN + telegram_chat_id in user doc
      - Skips if welcome_telegram_sent_at is truthy
      - Writes welcome_telegram_sent_at on success
    """
    chat_id = str((doc or {}).get("telegram_chat_id") or "").strip()
    already = str((doc or {}).get("welcome_telegram_sent_at") or "").strip()
    if already:
        return {"sent": False, "reason": "telegram_already_sent"}

    if not TELEGRAM_BOT_TOKEN:
        return {"sent": False, "reason": "telegram_token_missing"}

    if not chat_id:
        return {"sent": False, "reason": "telegram_chat_id_missing"}

    try:
        r = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id": chat_id, "text": WELCOME_SMS},
            timeout=10,
        )
        if r.status_code >= 400:
            return {"sent": False, "reason": "telegram_send_failed", "error": f"HTTP {r.status_code}: {r.text[:200]}"}

        ref.set({"welcome_telegram_sent_at": now_iso()}, merge=True)
        return {"sent": True, "reason": "telegram_sent"}
    except Exception as e:
        return {"sent": False, "reason": "telegram_exception", "error": str(e)}

def main():
    db = firestore.Client(project=PROJECT_ID)
    uid = user_id_from_phone(PHONE_E164)

    watchlist = [x.strip() for x in WATCHLIST_NDCS.split(",") if x.strip()]

    ref = db.collection("users").document(uid)
    existing = ref.get().to_dict() or {}

    # keep existing created_at if present
    created_at = existing.get("created_at") or now_iso()

    doc = dict(existing)
    doc.update({
        "phone_e164": PHONE_E164,
        "watchlist_ndcs": watchlist,
        "status": "active",
        "created_at": created_at,
        "updated_at": now_iso(),
        "source": "manual_onboarding",
    })

    ref.set(doc, merge=True)

    tg = maybe_send_telegram_welcome(ref, doc)

    print("OK")
    print("user_id:", uid)
    print("phone_e164:", PHONE_E164)
    print("watchlist_ndcs:", watchlist)
    print("telegram:", tg)

if __name__ == "__main__":
    main()
