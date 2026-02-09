# Architectural Decisions — Glitch App

This file documents **intentional design decisions**.
Items here are **not bugs** and should not be “fixed” without revisiting product or ops goals.

---

## PAYMENTS_ENABLED Is a Global Kill Switch

**Decision**  
`PAYMENTS_ENABLED=false` disables *all outbound notifications*.

**Rationale**
- Operator safety valve for incidents
- Billing outages
- Maintenance windows
- Prevents revenue leakage during billing failures

**Important**
- This is separate from per-user billing enforcement
- Users must still have `status == "active"`

**Status**
Intentional. Do not change without ops review.

---

## Weekly Recap Counts Against Daily Alert Quota

**Decision**  
Weekly summary consumes **1 slot** from `MAX_ALERTS_PER_DAY`.

**Rationale**
- Absolute noise ceiling
- Users do not distinguish recap vs alert
- Prevents “20 alerts + 1 recap” spam days

**Alternative Considered**
Separate quota buckets — rejected for complexity.

**Status**
Intentional. Revisit only if users request.

---

## Stripe Webhook Re-Validates Watchlist Limits

**Decision**  
Watchlist limits are enforced:
- Once at checkout session creation
- Again at webhook activation

**Rationale**
- Checkout ≠ activation
- User may sit on Stripe page while limits change
- Activation-time environment wins

**Benefit**
Prevents activating users into invalid states.

**Status**
Intentional fail-closed behavior.

---

## Alert Fanout Requires Successful Shortage Upsert

**Decision**  
If shortage write fails → **no alerts sent**.

**Rationale**
- No write = unknown state
- Prevents duplicate or phantom alerts
- Enforces “write before side-effect” ordering

**Status**
Intentional database discipline.

---

## Name Resolution Cache Has No TTL

**Decision**
NDC name cache does not expire.

**Rationale**
- Drug names are stable
- Stale name ≠ correctness issue
- TTL adds complexity for marginal benefit

**Status**
Optimization deferred until cache size becomes material.

---

## UI Endpoints Fail-Closed on Firestore Errors

**Decision**
UI endpoints return `503` when Firestore errors occur.

**Rationale**
- Prevents partial or misleading diagnostics
- Encourages retry rather than false confidence

**Status**
Intentional safety behavior.

---

## Health Check Dual Routes

**Decision**
Expose both:
- `/healthz`
- `/healthz/`

**Rationale**
Different uptime monitors normalize trailing slashes differently.
Both are supported to avoid false negatives.

**Status**
Intentional compatibility behavior.

---

## Change Policy

Any change to these decisions must:
1. Update this file
2. Be justified in PR description
3. Consider ops, billing, and user trust impact
