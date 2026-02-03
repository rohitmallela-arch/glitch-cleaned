# Firestore Schema — Glitch App (Milestone B)

Design goals:
- Phone number is the account (low-touch onboarding)
- Deterministic watchlists (no bulk alert spam)
- O(1) fanout from FDA status change -> affected users
- Weekly recap via a single indexed query
- Durable outbound send log for idempotency and auditability

---

## Collections

### users/{user_id}

`user_id`: deterministic (e.g. u_<sha256(phone_e164)>)

Fields:
- phone_e164 (string, required)
- email (string, optional)
- telegram_chat_id (string, optional)
- status (string enum: active | trial | past_due | canceled | blocked)
- stripe_customer_id (string, optional)
- stripe_subscription_id (string, optional)
- created_at (timestamp)
- activated_at (timestamp, optional)
- next_weekly_due_at (timestamp, required once active)
- last_weekly_sent_at (timestamp, optional)
- initial_snapshot_sent_at (timestamp, optional)
- alerts_enabled (bool, default true)

Notes:
- Weekly dispatcher runs a single indexed query:
  status == "active" AND next_weekly_due_at <= now
  ORDER BY next_weekly_due_at ASC

---

### users/{user_id}/watchlist_items/{item_id}

V1 supports only deterministic NDC tracking.

Fields:
- kind (string enum: ndc)
- ndc (string, normalized 10/11-digit)
- label (string, optional, user-facing)
- active (bool, default true)
- created_at (timestamp)

item_id format:
- ndc_<normalized_ndc>

---

### ndc_watchers/{ndc}/watchers/{user_id}

Inverted index for fast fanout when an NDC status changes.

Fields:
- user_id (string)
- active (bool, default true)
- created_at (timestamp)

Purpose:
- Avoid scanning users/watchlists on every FDA poll
- Cost remains flat as user count grows

---

### events/{event_id}

Optional but recommended ledger of detected changes.

Fields:
- ndc (string)
- old_status (string)
- new_status (string)
- detected_at (timestamp)
- fingerprint (string; e.g. ndc:new_status:date_bucket)

Used for:
- Idempotency
- Debugging
- Replay safety

---

### outbound_messages/{message_id}

Durable record of outbound notifications.

Fields:
- user_id (string)
- channel (string enum: sms | telegram)
- type (string enum: initial_snapshot | change_alert | weekly_recap)
- payload (map)
- dedupe_key (string; e.g. weekly:<user_id>:<YYYY-WW>)
- created_at (timestamp)
- sent_at (timestamp, optional)
- status (string enum: queued | sent | failed)
- error (string, optional)

Purpose:
- Prevent duplicate sends
- Minimal support visibility
- Future audit trail

---

## Required Composite Indexes

### users
- status ASC
- next_weekly_due_at ASC

Used by weekly recap dispatcher.

