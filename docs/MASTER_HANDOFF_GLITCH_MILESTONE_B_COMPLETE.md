🧠 MASTER HANDOFF PROMPT — GLITCH APP (Milestone B COMPLETE → Next Work)

Last updated: 2026-01-31 (Asia/Jakarta)
Owner: Rohit Mallela
System: The Glitch App — FDA drug shortage alerts (Cloud Run + Firestore + Twilio + Telegram + Scheduler + Stripe)

0) ONE-LINE CONTEXT
Glitch is a live Cloud Run service that deterministically monitors FDA drug shortages, stores baseline state in Firestore, sends alert fanout only to watchlist-based subscribers (Twilio + Telegram), runs weekly recaps via Cloud Scheduler, and now includes a fully verified paid signup + activation pipeline via Stripe Checkout + Stripe Webhook.

1) CANONICAL DEPLOYMENT (DO NOT DEVIATE)
Cloud Run
- Project: theglitchapp
- Region: us-central1
- Service: glitch-webhook
- Canonical URL (use everywhere): https://glitch-webhook-129120132071.us-central1.run.app
- Verified revision: glitch-webhook-00071-pjh (100% traffic)

Health
- GET /healthz → 200 "ok"

2) STRIPE (TEST MODE) — VERIFIED END-TO-END ✅
Endpoints
- POST /create_checkout_session
  - Input JSON: phone_e164 (required), watchlist_ndcs (optional CSV), email (optional)
  - Returns: {"url": "<stripe checkout url>"} (HTTP 200)
  - Uses metadata: phone_e164, watchlist_ndcs (digits-only, comma-separated), email

- POST /stripe_webhook
  - Stripe signature verification enabled (Stripe-Signature header)
  - PAYMENTS_ENABLED gate enforced
  - Processes: checkout.session.completed
  - Returns: HTTP 200 for valid Stripe events

Environment / Config
PAYMENTS_ENABLED=true
STRIPE_PRICE_ID=price_1Sv5eSAbml4ATQdpoqzuV2RH
CHECKOUT_SUCCESS_URL=https://example.com/success
CHECKOUT_CANCEL_URL=https://example.com/cancel

Secret Manager (mounted into Cloud Run)
- STRIPE_API_KEY -> secret stripe_api_key_test:latest
- STRIPE_WEBHOOK_SECRET -> secret stripe_webhook_secret_test:latest

Runtime Service Account
- 129120132071-compute@developer.gserviceaccount.com
- roles/secretmanager.secretAccessor granted on both Stripe secrets

Verification proof (authoritative)
- Cloud Run request logs show /stripe_webhook status 200 with userAgent Stripe/1.0
- Firestore writes verified for test user:
  users/u_468a4b26753815290dc13ee82f453df24fd974c708542d1f3c497c7b4e7e4413
  - status=active
  - stripe_last_event=checkout.session.completed
  - initial_snapshot_sent_at present
  - watchlist_items contains: 0000202501, 0002821501
  - ndc_watchers/{ndc}/watchers/{user_id} exists for both NDCs

3) WATCHLIST-BASED FANOUT (NO BULK SPAM)
- Shortage baseline collection: drug_shortages
  - doc id = raw package_ndc (may include dashes)
  - derived field stored: ndc_digits (digits-only)
- Alerts fan out only to watchers:
  ndc_watchers/{ndc_digits}/watchers/{user_id}
- Users maintain watchlist:
  users/{user_id}/watchlist_items/{ndc_digits}

4) WEEKLY RECAP (CONFIRMED)
Endpoint
- POST /weekly_recap_run

Scheduler
- Job: projects/theglitchapp/locations/us-central1/jobs/glitch-weekly-recap
- Schedule: 0 9 * * 1 (Mon 09:00 UTC)
- OIDC invoker SA: glitch-scheduler-sa@theglitchapp.iam.gserviceaccount.com
- Cloud Run IAM: roles/run.invoker includes this SA
- Confirmed end-to-end: Scheduler → Cloud Run returns HTTP 200

5) CURRENT SAFE DEFAULTS
- Canonical URL for all integrations:
  https://glitch-webhook-129120132071.us-central1.run.app
- Watchlist-driven fanout only (no bulk alerting)
- Deterministic change detection only (alert only when prev_status != current_status)
- Secrets only via Secret Manager (never plaintext env vars)

6) WHAT TO DO NEXT (PRIORITIZED)
A) Onboarding surface
- Replace success/cancel URLs with Carrd routes
- Add “active + watchlist confirmed” confirmation page

B) Billing lifecycle hardening
- Handle invoice.payment_failed + customer.subscription.deleted:
  - set users/{user_id}.status="inactive"
  - disable alerts + weekly recaps
- Add Billing Portal link (Stripe customer portal)

C) Plan limits + abuse controls
- Cap watchlist size by plan
- Rate-limit create_checkout_session
- Add idempotency: store processed webhook event ids

D) Ops hardening
- Add structured logs for webhook event id/type/user_id (no secrets)
- Alert policy for /stripe_webhook 5xx spikes
- Optional canary: synthetic checkout session create

7) RESUME RUNBOOK (CLOUD SHELL)
cd ~/glitchapp_ops/src/workdir
export PROJECT_ID="theglitchapp"
export REGION="us-central1"
export SERVICE="glitch-webhook"
export CANONICAL="https://glitch-webhook-129120132071.us-central1.run.app"
gcloud config set project "${PROJECT_ID}"

Confirm health:
curl -sS -i "${CANONICAL}/healthz" | sed -n '1,40p'

Create a checkout session:
curl -sS "${CANONICAL}/create_checkout_session" \
  -H "Content-Type: application/json" \
  -d '{"phone_e164":"+15555550123","watchlist_ndcs":"0002821501,0000202501"}'

## Milestone E.2 — UI Diagnostics (Shortage-Aware)

Status: FROZEN  
Verified revision: glitch-webhook-00091-tk2

What was added:
- /ui/user/diagnostics now checks FDA shortage presence
- Queries Firestore drug_shortages by ndc_digits
- Adds NO_MATCHING_SHORTAGE gate
- Adds shortage object to output:
  - exists
  - doc_id
  - status

What this enables:
- Frontend can answer “Would an alert fire right now?”
- Distinguishes eligibility vs shortage absence
- Zero writes, zero side effects, safe for public UI

What it does NOT do:
- Does not send alerts
- Does not modify user state
- Does not imply shortage validity beyond existence

Canonical endpoint:
POST https://glitch-webhook-129120132071.us-central1.run.app/ui/user/diagnostics

Failure mode:
- Firestore read errors → fail-closed (503)

