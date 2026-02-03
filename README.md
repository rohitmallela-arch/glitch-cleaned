# Glitch App (Cloud Run) — Ops-clean repo

This repo contains the Cloud Run service for Glitch (FDA drug-shortage alerts).

## What's been cleaned / upgraded
- Removed local artifacts from the packaged repo output (no `.venv`, no `__pycache__`, no `*.bak`).
- Tidied `main.py` imports and removed a duplicated Twilio code block.
- Added a **thin Alert Rendering Layer** (presentation only):
  - `instant alert` rendering (`_render_instant_alert`)
  - `weekly summary` rendering (`_render_weekly_summary`)
- Added a **deterministic, versioned, cacheable name resolution pipeline** (best-effort):
  - `_resolve_name_best_effort` with versioned cache collection: `ndc_name_cache_<version>`
  - Alerts never block on name resolution.
- Upgraded `weekly_recap_run` to persist a first-class artifact in Firestore:
  - `weekly_summaries/{YYYY-Www}` document (confidence reset)
- Wired a first-pass `shortage_poll_run` that:
  - fetches FDA shortages feed (URL configurable via `FDA_SHORTAGE_URL`)
  - upserts canonical shortage docs (doc id == ndc_digits)
  - emits instant alerts on **status change** to watchers (`ndc_watchers/{ndc}/watchers/*`)

## Key env vars
Required for production:
- `GOOGLE_CLOUD_PROJECT` (Cloud Run provides)
- `PAYMENTS_ENABLED` (boolean gate)
- `FAIL_CLOSED_LIMITS` (boolean)
- `MAX_ALERTS_PER_DAY` (int)
- `MAX_ALERTS_PER_NDC_PER_DAY` (int)
- `WEEKLY_RECAP_MAX_ITEMS` (int)

Integrations:
- `TELEGRAM_BOT_TOKEN`
- `TWILIO_ACCOUNT_SID`
- `TWILIO_AUTH_TOKEN`
- `TWILIO_FROM_NUMBER`

Optional:
- `FDA_SHORTAGE_URL` (default: official FDA drugshortages.json)
- `NAME_RESOLUTION_VERSION` (default: v1)

## Firestore collections (high level)
- `users/{user_id}`
- `users/{user_id}/watchlist_items/{ndc}`
- `ndc_watchers/{ndc}/watchers/{user_id}`
- `drug_shortages/{ndc}` (canonical; legacy query fallback still exists for reads)
- `weekly_summaries/{week_key}`
- `ndc_name_cache_<version>/{ndc}`
