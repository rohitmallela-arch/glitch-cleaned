
## Canonical Cloud Run URL (Milestone B)
CANONICAL_RUN_URL=https://glitch-webhook-129120132071.us-central1.run.app

Note: `gcloud run services describe ... status.url` may return an `*.a.run.app` alias.
We treat the `*.run.app` hostname above as canonical for all external integrations (Carrd, Stripe, Scheduler).

## Milestone B — Stripe wiring (TEST) — FINAL VERIFIED (2026-01-31 UTC)

### Cloud Run (canonical)
PROJECT_ID=theglitchapp
REGION=us-central1
SERVICE=glitch-webhook
CANONICAL_RUN_URL=https://glitch-webhook-129120132071.us-central1.run.app
LIVE_REVISION=glitch-webhook-00071-pjh

### Stripe (TEST mode)
- /create_checkout_session returns 200 with Stripe Checkout URL
- /stripe_webhook receives Stripe events and returns HTTP 200
- Verified event: checkout.session.completed (status 200 in Cloud Run request logs)

STRIPE_PRICE_ID=price_1Sv5eSAbml4ATQdpoqzuV2RH
PAYMENTS_ENABLED=true

### Secret Manager (mounted into Cloud Run)
STRIPE_API_KEY secret:
- name: stripe_api_key_test
- version: latest
- mounted env var: STRIPE_API_KEY

STRIPE_WEBHOOK_SECRET secret:
- name: stripe_webhook_secret_test
- version: latest
- mounted env var: STRIPE_WEBHOOK_SECRET

Runtime SA (Cloud Run):
RUNTIME_SA=129120132071-compute@developer.gserviceaccount.com
Secret access:
- roles/secretmanager.secretAccessor on both secrets granted to RUNTIME_SA

### Firestore — activation pipeline verified
User doc:
users/u_468a4b26753815290dc13ee82f453df24fd974c708542d1f3c497c7b4e7e4413
- status=active
- stripe_last_event=checkout.session.completed
- initial_snapshot_sent_at present
Watchlist items:
- users/{user_id}/watchlist_items/{ndc_digits} created for 0000202501 and 0002821501
Watchers:
- ndc_watchers/{ndc_digits}/watchers/{user_id} created for both NDCs


### Milestone B freeze artifacts
MASTER_HANDOFF_FILE=docs/MASTER_HANDOFF_GLITCH_MILESTONE_B_COMPLETE.md
MASTER_HANDOFF_LAST_VERIFIED_REVISION=glitch-webhook-00071-pjh


## Milestone C — Billing lifecycle hardening — FINAL VERIFIED (2026-01-31 UTC)

### Cloud Run (canonical)
PROJECT_ID=theglitchapp
REGION=us-central1
SERVICE=glitch-webhook
CANONICAL_RUN_URL=https://glitch-webhook-129120132071.us-central1.run.app
HEALTH_PATH=/healthz/
LIVE_REVISION=glitch-webhook-00080-fof

### Deployment notes
- Health behavior:
  - GET /healthz/ => 200 {"ok":true} (canonical)
  - GET /healthz  => may return 404 (non-canonical; do not use for monitoring)
- Canary tags used:
  - canary-healthfix
  - canary-billinghardening

### Uptime check
UPTIME_CHECK_CONFIG=projects/theglitchapp/uptimeCheckConfigs/glitch-webhook-healthz-cloud-run-v2-XrqsmJ8BCqw
UPTIME_CHECK_PATH=/healthz/
UPTIME_CHECK_PERIOD=60s
UPTIME_CHECK_TIMEOUT=10s

### Stripe webhook hardening (TEST mode)
STRIPE_PRICE_ID=price_1Sv5eSAbml4ATQdpoqzuV2RH
PAYMENTS_ENABLED=true

WEBHOOK_IDEMPOTENCY_STORE=processed_stripe_events/{event_id}
BILLING_FAIL_CLOSED=true

Handled Stripe events:
- checkout.session.completed -> status=active + activation pipeline
- invoice.payment_failed -> status=suspended + billing_disabled_at
- customer.subscription.deleted -> status=canceled + billing_disabled_at

Structured logs (no secrets):
- event_id, event_type, user_id, customer, subscription

### Milestone C freeze marker
MILESTONE_C_STATUS=FROZEN
MILESTONE_C_LAST_VERIFIED_REVISION=glitch-webhook-00080-fof

## Milestone C.1 — Alert eligibility enforcement — FINAL VERIFIED (2026-01-31 UTC)

### Enforcement point
ELIGIBILITY_GUARD=_send_message_best_effort
FAIL_CLOSED=true

Eligibility rule:
- users/{user_id}.status == "active" → notifications allowed
- status != "active" or missing → notification skipped

Applies to:
- Initial snapshot
- FDA status-change alerts
- Weekly recap
- Any future notification path

Structured log on skip:
- notify_skip_ineligible user_id=<id> status=<status>

### Cloud Run
LIVE_REVISION=glitch-webhook-00080-fof
DEPLOY_TAG=canary-eligibilitygate

### Milestone C.1 freeze marker
MILESTONE_C1_STATUS=FROZEN
MILESTONE_C1_LAST_VERIFIED_REVISION=glitch-webhook-00080-fof

## Traffic & rollback posture — FINAL VERIFIED (2026-01-31 UTC)

PROD_REVISION=glitch-webhook-00080-fof
ROLLBACK_REVISION=glitch-webhook-00077-rom
ROLLBACK_TAG=rollback-billinghardening

Rollback URL (tagged):
https://rollback-billinghardening---glitch-webhook-dmsse4fh6q-uc.a.run.app

Notes:
- Legacy canary tag removed: canary-healthfix
- Canonical external hostname remains the *.run.app URL (Carrd, Stripe, Scheduler).

### Milestone C.2 freeze marker
MILESTONE_C2_STATUS=FROZEN
MILESTONE_C2_LAST_VERIFIED_REVISION=glitch-webhook-00084-kzv
MILESTONE_C2_VERIFIED_AT=2026-01-31

### Milestone C.2 — Fail-Closed Enforcement Guarantee

- If rate-limit state cannot be read, written, or transactionally updated:
  - NO notification is sent
- If any plan limit env var is missing or malformed:
  - Request fails closed
- If Firestore transaction fails:
  - Notification is skipped
  - Structured log emitted: rate_limit_state_error

There is no fallback, retry, or client-side override path.

### Milestone C.2 — Verified Env Var Snapshot

PAYMENTS_ENABLED=true
MAX_WATCHLIST_ITEMS=25
MAX_ALERTS_PER_DAY=20
MAX_ALERTS_PER_NDC_PER_DAY=3
WEEKLY_RECAP_MAX_ITEMS=20
FAIL_CLOSED_LIMITS=true
ROLL_MARKER=<present>

STRIPE_API_KEY=SecretManager:stripe_api_key_test:latest
STRIPE_WEBHOOK_SECRET=SecretManager:stripe_webhook_secret_test:latest

## Current Production Snapshot — VERIFIED (2026-02-01)

Canonical external hostname (used for Stripe/Carrd/Scheduler):
https://glitch-webhook-129120132071.us-central1.run.app

Cloud Run default service URL (shown by `status.url`, not used for integrations):
https://glitch-webhook-dmsse4fh6q-uc.a.run.app

Health endpoint (canonical):
/healthz/  (note trailing slash)

LIVE_REVISION=glitch-webhook-00097-xed
Traffic=100% (verify via `status.traffic`)

Notes:
- Cloud Run `status.url` often shows the *.a.run.app URL even when the canonical *.run.app hostname is used externally.
- All external integrations must continue using the canonical *.run.app hostname.
- Use /healthz/ (with trailing slash) to avoid 404 ambiguity.

## Milestone D.1 — Public System Transparency (/ui/status) — VERIFIED (2026-02-01)

Endpoint:
- GET /ui/status  (and /ui/status/)

Guarantees:
- No secrets returned
- No Firestore reads/writes
- No user data returned
- Exposes only:
  - PAYMENTS_ENABLED (boolean)
  - plan limit env vars
  - roll_marker_present
  - Cloud Run service + revision metadata
  - canonical health path (/healthz/)
  - hostname guidance (use *.run.app externally)

Verified:
- HTTP 200 on canonical external hostname:
  - https://glitch-webhook-129120132071.us-central1.run.app/ui/status
- HTTP 200 on tagged URL:
  - https://canary-ui-status---glitch-webhook-dmsse4fh6q-uc.a.run.app/ui/status

Cloud Run:
- LIVE_REVISION=glitch-webhook-00097-xed
- TAG=canary-ui-status
- Traffic=100% (verified via status.traffic)

## Milestone D.2 — User Transparency (/ui/user/status) — VERIFIED (2026-02-01)

Endpoint:
- POST /ui/user/status  (and /ui/user/status/)
- Input: {"phone_e164":"+E164"}

Output (read-only):
- user: user_id, phone_e164, status, created_at, updated_at
- watchlist: count + deterministic preview (cap 10), scan_cap=200
- limits: env-based plan limits
- notes: enforcement explanation

Guarantees:
- No secrets returned
- No Firestore writes
- Fail-closed: if Firestore read fails -> 503 {"ok":false,"error":"unavailable"}
- Phone must be E.164 (+ prefix) or request fails 400

Verified:
- HTTP 200 on canonical external hostname:
  - https://glitch-webhook-129120132071.us-central1.run.app/ui/user/status
  - Example payload used: {"phone_e164":"+15555550123"}
- HTTP 200 on tagged URL:
  - https://canary-ui-user-status---glitch-webhook-dmsse4fh6q-uc.a.run.app/ui/user/status

Cloud Run:
- LIVE_REVISION=glitch-webhook-00097-xed
- TAG=canary-ui-user-status
- Traffic=100% (verified via status.traffic)

### Milestone D.2 completion addendum
- TAG=canary-ui-user-status
- Traffic=100% (verified via status.traffic)

## Milestone E.0 — UI CORS Enablement (Carrd Embedding) — VERIFIED (2026-02-01)

Scope:
- Adds CORS headers ONLY for /ui/* endpoints
- No CORS behavior change for non-/ui endpoints

Behavior:
- GET /ui/status and POST /ui/user/status return:
  - Access-Control-Allow-Origin: *
  - Access-Control-Allow-Methods: GET, POST, OPTIONS
  - Access-Control-Allow-Headers: Content-Type
- OPTIONS preflight for /ui/* returns 204 with:
  - Access-Control-Max-Age: 3600

Verified:
- Canonical hostname includes CORS headers when Origin is present:
  - Origin tested: https://carrd.co
  - GET https://glitch-webhook-129120132071.us-central1.run.app/ui/status => 200 + CORS headers
  - OPTIONS https://glitch-webhook-129120132071.us-central1.run.app/ui/user/status => 204 + CORS headers

Cloud Run:
- LIVE_REVISION=glitch-webhook-00097-xed
- TAG=canary-ui-cors
- Traffic=100% (verified via status.traffic)

### Milestone E.1 freeze marker
MILESTONE_E1_STATUS=FROZEN
MILESTONE_E1_LAST_VERIFIED_REVISION=glitch-webhook-00099-tuy
MILESTONE_E1_ENDPOINTS=/ui/user/diagnostics (POST)
MILESTONE_E1_GUARANTEES=read-only;no-secrets;firestore-reads-only;fail-closed-on-firestore-errors;cors-ui-only;deterministic-first-fail-decision-tree
MILESTONE_E1_INPUTS=phone_e164(required,+E164);ndc_digits(optional,digits-only)
MILESTONE_E1_OUTPUTS=checks[];decision.primary_reason_code;limits snapshot;rate_limits snapshot;user snapshot (no writes)
MILESTONE_E1_NOTE=Explains eligibility gates only (user/billing/watchlist/limits). Does not prove shortage existence.


### Milestone E.2 freeze marker
MILESTONE_E2_STATUS=FROZEN
MILESTONE_E2_LAST_VERIFIED_REVISION=glitch-webhook-00091-tk2
MILESTONE_E2_ENDPOINTS=/ui/user/diagnostics (POST)
MILESTONE_E2_ADDED=shortage_presence_check (drug_shortages collection by ndc_digits)
MILESTONE_E2_GUARANTEES=read-only;no-secrets;firestore-reads-only;fail-closed-on-firestore-errors;cors-ui-only;deterministic-first-fail-decision-tree
MILESTONE_E2_DECISION=primary_reason_code may be NO_MATCHING_SHORTAGE; eligible_to_alert_now false when shortage absent
MILESTONE_E2_OUTPUTS_ADDED=shortage{exists,doc_id,status};checks+=NO_MATCHING_SHORTAGE
MILESTONE_E2_NOTE=Adds “Would an alert fire?” answer by checking shortage existence. Still does not send alerts or write state.

