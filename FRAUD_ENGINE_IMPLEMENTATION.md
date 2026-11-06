# Problems 3 & 4 — Production-Oriented Implementation

## What is implemented

### Problem 3 — Card testing / carding
The live payment path now evaluates:
1. repeated failures on the same payment-method fingerprint;
2. distinct payment methods used by the same checkout session;
3. distinct payment methods observed from the same IP;
4. distinct payment methods observed for the authenticated account;
5. short-window failed-attempt bursts;
6. existing session/account blocks.

### Problem 4 — Rapid automated payment attempts
The live payment path now evaluates:
1. inter-payment timing;
2. repeated fast-payment strikes in a rolling window;
3. short-window attempt bursts;
4. network-address changes during the checkout session.

### Common decision layer
Both problem areas feed the same configurable risk score. The result is one of:
- `ALLOW`
- `STEP_UP_REQUIRED`
- `REVIEW`
- `BLOCK`

High-confidence carding/bot rules can immediately freeze the affected session/account. Lower combined risk can require additional verification instead of immediately blocking the customer.

## No fraud thresholds in application code
All fraud thresholds, windows, block duration, risk weights and decision boundaries are in `fraud_policy.json`.

Change the JSON policy rather than editing Python when tuning the rules. `fraud_policy.py` validates the policy when the application starts.

## Payment-data boundary
The customer checkout no longer sends raw card number/CVV to the fraud endpoint. It sends:
- an opaque `payment_method_token`;
- a provider-style `payment_method_fingerprint`;
- an idempotency key;
- the authorization result from the payment-provider boundary.

The included `payment_gateway.py` is deliberately a local simulated provider. It is for testing the fraud workflow and does not charge a card.

For a real deployment, replace the simulated provider with the chosen PCI-compliant payment provider's server-side adapter and use that provider's hosted/tokenized payment fields. Do not pass raw PAN/CVV into TradeVerify.

## Idempotency
Every live checkout attempt requires an idempotency key. A repeated request with the same account + idempotency key returns the previously stored result instead of recording another fraud event.

## Test UI
`checkout.html` is the normal customer-facing flow and has no attack-simulation buttons.

`fraud-test.html` is a separate developer/test page. It sends opaque simulated tokens through the same live fraud endpoint so Problems 3 and 4 can be verified without contaminating the customer checkout UI.

## Production configuration
For a single local test process, the in-memory state store can be used.

For multiple production workers/instances:
- configure `REDIS_URL`;
- install the `redis` dependency from `requirements.txt`;
- use a production secret manager rather than a checked-in `.env`;
- configure `SCOUT_API_KEY` for server-to-server fraud event ingestion;
- configure `ADMIN_PASSWORD` separately for human admin operations;
- set `PAYMENT_PROVIDER_MODE` to the adapter used by the deployment.

## Important boundary
This ZIP is a production-oriented fraud-engine implementation, not a claim that the complete TradeVerify application is production-certified. Before real payment traffic, the remaining deployment work includes the actual payment provider integration, shared production database/session storage, Redis operations, TLS/reverse proxy, load/soak testing, secrets management, observability, fraud-model tuning and operational approval.


## Demo payment behavior

The customer checkout no longer treats a particular card number as the success card. Any entered test card value is converted in the browser to an opaque demo token/fingerprint. The local simulated provider authorizes demo payments by default so the fraud engine can be exercised independently of a real acquirer. Controlled declines are available only to the developer Fraud Test Lab when the payment-simulation policy permits them. In production, replace the simulated provider with a real provider's hosted/tokenized payment fields and provider-issued authorization result.


## v4 Unified UX
The customer payment journey is integrated into the authenticated TradeVerify dashboard as an in-page payment drawer. The normal user does not navigate to a separate checkout page. Fraud testing is also exposed only through an admin/developer drawer on the same dashboard. The visual system uses the dashboard's white, charcoal/black, yellow, and neutral-gray palette.

Production note: the local demo still uses an opaque simulated token. A live deployment should mount provider-hosted/tokenized payment fields (for example a payment provider's embedded component) and send only provider-issued tokens/fingerprints to the fraud service.


## v6 checkout integration
The customer checkout uses the same fraud engine as the development harness, but the normal payment path does not expose test controls. Pre-authorization events are outcome-unknown; provider success/failure is recorded only after Stripe returns the result.

## Development customer-payment test flow (v7)

When `PAYMENT_PROVIDER_MODE=local_test`, the normal customer payment drawer exposes card number, expiry, and CVV fields. This is a development-only provider. The browser validates the entered test card, derives an opaque SHA-256 fingerprint/token, and sends only those opaque values plus the configured test outcome to TradeVerify. Raw PAN/CVV are not sent to or stored by the server.

The exact same Problems 3 and 4 fraud engine is then used:
- Pre-check registers the customer payment attempt and evaluates carding/bot velocity before the local provider outcome is applied.
- The local provider outcome is then recorded as the authoritative test success/failure.
- A third failure on the same payment fingerprint within the configured five-minute window activates the carding block for subsequent attempts.
- Four distinct payment fingerprints within the configured two-minute window, with the required failures, activates the distinct-method carding rule.
- Five failed attempts in the configured thirty-second burst window activates the failed-attempt burst rule.
- Rapid payment submissions under the configured 800ms human gap create bot strikes; the configured strike/burst thresholds can block the session/account.

This mode does not contact Stripe, a bank, or any payment network and must never be enabled in production. When the client's actual gateway is known, switch `PAYMENT_PROVIDER_MODE` to the corresponding provider adapter and test with that provider's sandbox/test credentials.


## v10 fixes (Problems 3 & 4 verified end-to-end over HTTP)

1. **Double-counted bot timing (Problem 4).** In local-test mode the confirm step timed the same customer payment a second time, milliseconds after precheck. Every normal payment therefore looked like a bot ("gap 0.9 ms"), and a customer with only a few declines at human speed could be frozen as an automated attacker. Confirm now reuses the timing result recorded at precheck: one customer attempt = one timing event.
2. **Decision bands did not match `fraud_policy.json`.** `allow_below` was ignored (everything under 60 was ALLOW) and `REVIEW` could never be returned. `_risk_decision` now uses: below `allow_below` = ALLOW, below `step_up_below` = STEP_UP_REQUIRED, below `block_at_or_above` = REVIEW, otherwise BLOCK.
3. Added `logs/test_payment_fraud_problems_3_4.py` (regression tests).

### Known policy decision (not changed)
The "distinct payment methods" rule also counts methods per IP address. Several genuine customers behind one office/NAT address can add up to the threshold. Tune `carding.distinct_payment_methods` in `fraud_policy.json` if the client's customers share addresses.

## v11: Fraud Test Lab panel (demo of Problems 3 and 4)

`integrated_payment.js` already contained the test-button code, but `index.html` had no panel for it, so `fraud-test.html` opened a page with no controls. The panel is now in `index.html` and is reachable from the payment drawer (button "Open Fraud Test Lab", visible only when `PAYMENT_PROVIDER_MODE=local_test`).

- **Problem 4 button:** 6 successful payments 150 ms apart (a person cannot click this fast). Expected: blocked on attempt 4, "automated payment activity detected".
- **Problem 3 button:** 4 different cards, all declined, 1.5 s apart. Expected: blocked on attempt 4, "card-testing pattern detected".
- Each run uses a fresh session and card id, so only the intended rule can fire. If the logged-in account is already locked by an earlier test, the panel says so and asks you to clear it in Admin (or restart the server).
- The panel calls `/api/admin/fraud-test-event`, which the server refuses unless `ENVIRONMENT=development`.

## v12: Problem 3 rules that protect genuine customers

| Rule | What it does | Where |
|---|---|---|
| R1 (existing) | Same card fails 3 times in 5 minutes: block | `carding.same_payment_method_failures` |
| R2 | The customer is told how many tries are left before the pause ("tries_left") | UI message + `attempts_remaining` |
| R3 | A successful payment clears THAT card's earlier failures (typo recovery). Session and account counters are not cleared, so one good card cannot reset an attack | `record_card_authorization` |
| R4 | 5 failed payments on one account within 10 minutes (any cards, any sessions): block. Catches bots that rotate session ids and cards | `carding.account_failures` |
| R5 | Locks last 15 minutes (was 60) and the message says how long; admin Clear All also works | `carding.block_duration_seconds` |
| R6 | Local test provider `by_card` mode: cards whose last 4 digits are in `LOCAL_TEST_DECLINE_SUFFIXES` (default `0002`) decline; all others succeed. Only the last 4 digits ever leave the browser | `local_test_payment.py` |

Fraud Test Lab now has four buttons: same card fails 3 times (Problem 3), bot speed (Problem 4), genuine customer, and 4-card sweep.
To pay the same invoice again after a successful test payment, delete `payment_ledger.json` and restart the server.


> **Note (v23):** the v13, v14 and v16/v17 sections below describe `bot.strike_count = 1` (block on the first too-fast payment). That was superseded in v18: the current value in `fraud_policy.json` is `2` (warn first with "Please slow down", block on a repeat within 30 s). Sections are kept as history; v18 is the current behaviour.

## v13: Problem 4 (bot-speed) - alert, block and admin unblock

**Behaviour.** A payment that arrives sooner after the previous one than a person can manage (`bot.minimum_human_gap_ms`, 800 ms) is treated as a bot signal. With `bot.strike_count = 1` (the default) the account is blocked immediately and the customer sees, at that moment, a red alert: "Account may be under attack by a bot ... this account has been blocked for security."

| Piece | What changed |
|---|---|
| Detection | `record_transaction_event` blocks the session AND the account on the first too-fast payment and records why (type, reason, gap in ms, time). |
| Alert | Checkout drawer and Fraud Test Lab show a red bot alert (`block_kind: "bot"`). Card-testing blocks keep their own wording. |
| Account block | The whole account is blocked, so opening a new browser session does not get around it. Login is refused too, with a clear message. |
| Admin | `admin.html` lists each blocked account once with a BOT ATTACK SUSPECTED / CARD TESTING label, reason, time, and refreshes every 3 seconds. "Unblock" clears the account and session blocks and resets the speed counters. |

**Tuning.** `fraud_policy.json` -> `bot.strike_count`: `1` = block on the first too-fast payment (current), `2` = allow one warning first (safer against a genuine user who double-taps).

Tests: `python logs/test_payment_fraud_problems_3_4.py`.


## v14: Problems 3 and 4 together (current behaviour; supersedes the counts in the v12 and v13 notes)

**Problem 3: back-to-back card failures (stolen card testing)**
- 4 failed payments in a row on the same card, OR 4 failed payments in a row on the account across any cards/sessions (`carding.same_payment_method_failures.count`, `carding.account_failures.count`, both 4): the account is blocked.
- The checkout tells the customer how many tries are left ("tries_left") before the pause.
- A successful payment ends the streak (typo/expired-card recovery). Failures older than the window (5 min per card, 10 min per account) do not count.
- Also blocked: 4 different cards within 2 minutes with at least 2 failures (card sweep), and 5 attempts with failures within 30 seconds.

**Problem 4: payment speed no human can reach**
- A payment sent less than 800 ms after the previous one (`bot.minimum_human_gap_ms`) blocks the account immediately (`bot.strike_count = 1`) and shows a red "Account may be under attack by a bot" alert at that moment.

**Both**
- The whole ACCOUNT is blocked (not just the browser session), login is refused with a clear message, and the block lasts `carding.block_duration_seconds` (15 minutes) unless the admin unblocks sooner.
- `admin.html` lists each blocked account once, labelled BOT ATTACK SUSPECTED or CARD TESTING, with the reason and time. It refreshes every 3 seconds. "Unblock" restores the account and clears the session block and speed counters.
- Fraud Test Lab (development only) has four buttons: stolen card 4 failures, bot speed, genuine customer, 4-card sweep.
- Local test provider `by_card` mode: cards ending in `0002` decline, every other card is approved.

Tests: `python logs/test_payment_fraud_problems_3_4.py` and `python logs/test_account_scout.py`.


## v15: test reset (development only)

An approved test payment marks the invoice paid in `payment_ledger.json`, so later attempts on it are refused with "already paid" before the fraud engine sees them (nothing failed, so nothing is counted). To test failures use a card ending in `0002`. The Fraud Test Lab has a **Reset test invoice and blocks** button (`POST /api/admin/fraud-test-reset`, needs a logged-in session, refused unless `ENVIRONMENT=development`) that marks the invoice unpaid and clears every block and counter, so no server restart or file deletion is needed between demos.


## v16/v17: Problem 4 speed rules (automatic, on the real payment screen)

Every payment attempt is timed automatically at the FIRST step of checkout (`create-intent`), before an invoice can be refused as already paid, so a bot cannot hide behind "already paid" or "invalid invoice" errors. Precheck reuses that timing, so one attempt is counted once. No special button or lab is needed: pressing Pay fast, or a script calling the API, is detected on its own.

| Rule | Setting in `fraud_policy.json` (`bot`) | Catches |
|---|---|---|
| Gap | `minimum_human_gap_ms` 800, `strike_count` 1 | a payment less than 0.8 s after the previous one |
| Rate | `rate_limit_count` 4 within `rate_limit_window_seconds` 4 | about one payment per second or faster; "10 payments in 10 seconds" is stopped at payment 4, after 3 seconds |

The rate is counted per ACCOUNT, so changing session ids does not help a bot. Either rule blocks the account and session, shows the red "Account may be under attack by a bot" alert on the payment screen, and lists the account in `admin.html` as BOT ATTACK SUSPECTED with the reason. Admin "Unblock" clears the block and the counters. Problem 3 logic is unchanged; a person pacing attempts 1.5 s or more apart is never flagged by the speed rules.
Limit: this front-door timing is wired into the local test checkout; the Stripe checkout path keeps its previous timing point.


## v18: warn first, then block (Problem 4) and a clean client version

**Warn first.** `bot.strike_count` is now 2. The first too-fast payment, or the first time the rate limit is hit, is refused with HTTP 429 and the message "Please slow down ...". Nothing is blocked. A repeat within `bot.strike_window_seconds` (30 s) blocks the account and shows the red bot alert. Strikes are counted per ACCOUNT, expire by themselves, and are cleared by admin Unblock. A double-click or browser retry is therefore only warned. Set `strike_count` to 1 to block on the first offence.
- One payment per second: warning at payment 4, block at payment 5. Payments 0.1 s apart: warning at payment 2, block at payment 3.
- (Superseded in v29: a Cloudflare Turnstile human-check now accompanies the 429 "slow down" step when configured.) A CAPTCHA was not built at this point; the 429 "slow down" step is the first stage. The Stripe checkout path keeps its previous timing point.

**Clean client version.** The Fraud Test Lab buttons (and the dev endpoints `/api/admin/fraud-test-event` and `/api/admin/fraud-test-reset`) are OFF by default. They work only when `ENVIRONMENT=development` AND `ENABLE_TEST_LAB=1`. Without the flag the payment screen shows just the normal form and the server answers 403 to the lab endpoints.


## v19: automatic security badge (replaces the manual simulator in the header)

The header no longer needs the "Scout Security" scenario dropdown. It shows the logged-in account's REAL state, refreshed every 3 seconds from `POST /api/account/security-status`: green "Protected: no threats", amber "Warning: N failed payments" / "Warning: payments too fast", red "Blocked: bot activity" / "Blocked: card testing". The old dropdown (a canned demo simulator) stays hidden unless `ENABLE_TEST_LAB=1`. Engine function: `account_scout.account_security_status()`.


## v23: double-click guard, admin audit trail, restored security badge

- **Double-click guard (browser).** A second click on Pay while a payment is in flight, or within 1.2 s of the previous submit, is ignored client-side, so a genuine accidental double-click never reaches the server and never counts as a bot strike. The server-side "slow down" warning and strike rules are unchanged and still catch real scripts.
- **Admin audit trail.** Every admin Unblock is appended to `admin_audit.log` (JSON lines: time, admin name, key, whether it cleared, client IP). `admin.html` has a "Your name" field and shows the 50 most recent actions (`GET /api/admin/audit`, same admin password). Limitation: there is still one shared admin password, so the name is self-declared, not authenticated.
- **Header.** The live "Account security" badge (real state, from `/api/account/security-status`) is back in the header after the v21 redesign dropped it.


## v26: approve_by_card test mode (reverse of by_card)

`LOCAL_TEST_PROVIDER_OUTCOME=approve_by_card`: ONLY cards whose last 4 digits are in `LOCAL_TEST_APPROVE_SUFFIXES` (default `0002`) are approved; every other card is declined. This makes Problem 3 easy to try on the payment page: type any normal-looking card number repeatedly to fail, and use a card ending `0002` for the one successful payment. `start.bat` / `start.sh` now use this mode. The old `by_card` mode (decline only `0002`) still works.


## v28: block reference IDs (#4) and escalating locks + OTP self-unlock (#3)

**Reference ID.** Every fraud incident gets a short case number (`TV-83F2A1`). All keys blocked in the same incident (session, account, card) share it. It is shown to the customer under the blocked payment message and in the header-badge tooltip, and to support on `admin.html` (`Ref ...`, lock level, MANUAL REVIEW flag). It is stored in the block's `meta` (`reference`, `lock_level`, `lock_seconds`, `needs_review`).

**Escalating locks** (`fraud_policy.json` -> `escalation`, applied in `account_scout._block_key`). Counted per account over `history_window_seconds` (24 h):

| Lock in 24 h | Length | Who can lift it |
|---|---|---|
| 1st | `block_duration_seconds` (15 min, unchanged) | customer (OTP) or admin |
| 2nd | 60 min | admin, or waits out the time |
| 3rd and later | 24 h, flagged `needs_review` | admin only |

**OTP self-unlock** (`account_unlock.py`, endpoints `POST /api/account/unlock-request` and `/api/account/unlock-verify`). Only for a first-time lock (`self_unlock_max_level: 1`). A 6-digit code is emailed to the account owner (same delivery as login; shown on screen only when `ENVIRONMENT=development`). Code lives 5 min, 3 wrong tries, 30 s resend cooldown. A right code clears the whole incident (account, session, card keys) plus the failure counters tied to them, and writes a `self_unlock` entry to `admin_audit.log`.

**Known limits.** (1) A customer who is *already logged in* when blocked can self-unlock; a blocked account still cannot log in again (existing behaviour, unchanged). (2) Lock history is kept in memory per server process, so it resets on restart and is not shared across several servers; use Redis for that. (3) Unlocking does not erase failure counters for a card the engine never tied to the incident, so repeating the same declined card can re-block quickly, and that re-block counts as a repeat (level 2). (4) `lock_durations` and thresholds are starting values, not tuned on real traffic.

Tests: `python logs/test_escalation_unlock.py`.


## v29: human check (Cloudflare Turnstile) on the first too-fast payment

**Choice.** Cloudflare Turnstile: free, usually invisible to real people (no image puzzles), no Google account needed, and Cloudflare publishes test keys, so it can be demonstrated without signing up.

**Flow.** First too-fast payment (strike 1) -> the server refuses it with HTTP 429 "slow down" and adds `captcha_required` + the public site key. The payment drawer shows the Turnstile widget. The person solves it -> `POST /api/payments/captcha/verify` -> the server confirms the answer with Cloudflare's `siteverify` -> that person's speed strikes are cleared and they carry on. A bot that ignores or fails the check makes another too-fast payment = strike 2 = block (the existing rule, unchanged).

**Safeguards (`captcha.py`).** Fails CLOSED (any error reaching Cloudflare = not verified). Max 2 passes per account per hour (`fraud_policy.json` -> `captcha.max_passes_per_hour`), so a bot cannot solve its way out forever. A check can never lift an existing block. Off unless `CAPTCHA_PROVIDER=turnstile` and both keys are set, so behaviour is unchanged without it.

**Configuration.** `CAPTCHA_PROVIDER=turnstile`, `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET_KEY`. `start.bat` / `start.sh` use Cloudflare's published TEST keys (the widget always passes), which demonstrates the flow but gives NO real bot protection. For real use, create a free Turnstile site in the Cloudflare dashboard and put the real keys in those variables.

**Needs internet.** The browser loads the widget from `challenges.cloudflare.com` and the server calls `siteverify`. Offline, the page shows "the check could not load" and the plain warning still applies.

**Not covered.** The self-unlock (one-time code) screen has no CAPTCHA yet. Tests: `python logs/test_captcha.py` (Cloudflare is stubbed, no internet needed).


## v30: stronger bot detection, human check before the card-testing block, admin stats

**Extra bot signals** (`bot_signals.py`, policy `fraud_policy.json` -> `hardening`). They share the speed rule's strike counter: first = warning (with the human check if enabled), a repeat within the strike window = block.
- **Form-fill time.** The page tells the server when the payment form opens (`POST /api/payments/form-opened`). Card details arriving less than `min_fill_ms` (1500) later, or a payment with no form opened at all, is a strike. A script that skips the page is therefore caught on its first payment.
- **Steady rhythm.** 5 payments whose 4 gaps are within `max_variation` (8 percent) of each other and under 15 s apart are machine-regular. People are irregular. This catches bots that wait exactly N seconds, which the 0.8 s rule misses. The history is kept after a warning, so a script that carries on is blocked on its next payment; a person who pauses breaks the pattern.
- Unblocking (admin or self-unlock) clears the rhythm history.

**Human check before the card-testing block** (`captcha.card_gate`, opt-in with `CAPTCHA_ON_CARD_FAILURES=1`, needs the Turnstile keys). After 3 failed payments on the account, the next card needs a human check (HTTP 428). A passed check allows exactly ONE more attempt; if it fails too, the 4th failure blocks as before. A bot cannot keep guessing cards. Off by default because it needs internet: offline the widget cannot load and the demo of the block would be stuck.

**Admin stats** (`GET /api/admin/stats`, "Last 24 hours" card on `admin.html`): blocks (bot, card testing, repeat locks), self-unlocks, admin unblocks, and the share lifted early. A high "lifted early" share means genuine customers are being caught, so loosen that rule. In memory: resets on restart.

**Deliberately not built.** (1) "Block the card first, not the whole account": it would change the behaviour you validated (4 failures block the account) and the account-level lock, reference ID and self-unlock all rely on that. (2) Server-side duplicate-click suppression: the disabled Pay button already stops a double-click, and a duplicate allowance would be a loophole that delays the "third fast payment blocks" rule.

**Limits.** Fill-time and rhythm state is per process (in memory). Only the local test payment path is hooked, not the Stripe `/api/payments/create-intent` path. Thresholds are starting values.

Tests: `python logs/test_bot_signals.py`.


## v31: admin stats counted one incident several times (fixed)

One fraud incident blocks several keys (session, account, card), so pressing "Clear All" wrote several audit lines and the "Last 24 hours" card showed impossible figures such as "3 admin unblocks" for 2 blocks and "150% lifted early". Audit entries now store the incident reference ID, and the stats count each incident once by that reference (older lines without one are grouped per account within 5 s and are not used for the percentage). The percentage only counts incidents that are in the 24 h window and is capped at 100. The audit list on `admin.html` now shows `Ref TV-...` per line.


## v32: a different account no longer inherits the previous account's session block (fixed)

**Bug.** A block on a browser checkout session (`session:checkout-...`) was applied to ANY account using that browser tab. After account A was blocked, logging in as account B in the same tab (new account, different card) still showed A's "card-testing pattern detected" message, and B's header badge stayed clean while its payments were refused.

**Fix (two layers).**
1. Server (`account_scout._session_block_applies`): a session block belongs to the account that caused it (`meta.account_id`). Another account is not refused because of it. Account blocks and card blocks are unchanged: the blocked account stays blocked everywhere, and a blocked card stays blocked for everyone. A session block with no owning account still applies to everyone.
2. Browser (`integrated_payment.js`): a new login (new session token) starts a fresh checkout session id, so the tab no longer carries the previous account's id.

**Also fixed (my v30 slip).** The extra bot checks (form-fill time, rhythm) no longer run on top of an account that is already blocked by the card-testing rule, which could show a confusing "looks automated" message instead of the block message.

**Known limit.** Failure-burst counters (5 attempts with failures within 30 s) are still keyed by session and IP. Two accounts failing within the same 30 s from one browser session and IP can still add up; switching accounts needs a login and one-time code, which takes longer than that, and the new session id above removes the shared session anyway.

Tests: `python logs/test_session_owner.py`.


## v33: admin stats no longer mix in other accounts' history

`admin_audit.log` is a permanent history of every account's unblocks and survives restarts, while the incident counters in memory start from zero at each start. v30/v31 counted old audit lines against the new counters, so the "Last 24 hours" card could show figures such as "200% lifted early" and "3 admin unblocks" that belonged to a previous account (for example an earlier test with another account). Now the card counts only audit lines tied, by reference ID, to an incident in the current counters (this server run), each incident once. Older lines stay visible in the history but are not counted. The history list on `admin.html` is now titled "Admin action history" and has a filter box (account, reference or admin name) so support can narrow it to one customer.


## v34: the newer protections now also run in Stripe mode

Until v33 the CAPTCHA, form-fill time, rhythm check and card-failure human check were wired only into the local test payment path. In Stripe mode (`PAYMENT_PROVIDER_MODE=stripe`):
- `POST /api/payments/create-intent` applies the card-failure human check (`captcha.card_gate`, opt-in) and answers 428 when it is needed.
- `POST /api/payments/precheck` now runs the extra bot signals and, on the first strike, answers 429 "slow down" (with the Turnstile human check when configured). Before v34 a first strike in Stripe mode was recorded but the payment still went ahead; a repeat blocks as before.
- Reference IDs, escalating locks, self-unlock, session-owner handling and the admin stats were already shared by both paths (they live in the block step).
- `start_stripe.bat` / `start_stripe.sh` start the server in Stripe test mode; paste your own TEST keys into them (no secrets are included).

**What was verified, and what was not.** Checked against a stand-in for Stripe (`logs/stripe_stub_server.py`, no keys or internet): a person passes; a 0.2 s repeat gets the warning then the block; a script that never opened the form gets the warning; an account with 3 declines gets the human check. NOT verified: a real Stripe test payment, Stripe-hosted card fields, 3-D Secure, and webhooks. Run those once with real test keys.

**Browser note.** The double-click guard is ON in Stripe mode, so fast clicks by hand are ignored; use the console script to trigger the speed rule.


## v35: alerts, email codes and web hardening

**Block alerts** (`alerts.py`). When the engine blocks an account, one message goes to `ALERT_WEBHOOK_URL` (Slack-style `{"text": ...}` incoming webhook) and/or `ALERT_EMAIL_TO` (same `SMTP_*` settings as codes). One alert per incident (not per blocked key); the message has the reference ID, account, lock level, reason and a link to `PUBLIC_BASE_URL/admin.html`. A repeat block of the same account within 60 s is not re-sent; a level-3 manual-review lock is always sent and marked URGENT; a flood guard caps non-urgent alerts per minute. Sending is in a background thread, so a dead Slack or SMTP can never fail or delay a payment. No card data is included.

**Email codes** (`auth_engine._send_otp`). Login codes were already emailed over SMTP/STARTTLS when `SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD` are set. Now: (1) the unblock code has its own email wording; (2) in production (`ENVIRONMENT=production`, which is also the default when it is not set) a code is NEVER returned to the browser and NEVER written to the log; if it cannot be emailed, login / unblock fails closed with a clear message. In development the code still shows on screen as before.

**Web hardening** (`security.py`, hooks in `server.py`):
- CORS: production allows only origins in `ALLOWED_ORIGINS` (the exact origin is echoed, never `*`); development keeps the old open behaviour.
- Security headers on every response: nosniff, frame denial, referrer policy, permissions policy, and a Content-Security-Policy that is REPORT-ONLY unless `CSP_ENFORCE=1` (the pages use inline scripts; check them in a browser before enforcing). HSTS with `HSTS=1` over https.
- Rate limits per client IP (`fraud_policy.json` -> `rate_limits`): login 10/min, one-time code check 10/min, register 10 per 5 min, unlock request 6 per 5 min, unlock verify 10 per 5 min, CAPTCHA verify 15 per 5 min, every `/api/admin/` call 40/min. Over the limit: HTTP 429 with `Retry-After`.
- Real client IP behind a proxy: `X-Forwarded-For` is believed only when the direct peer is listed in `TRUSTED_PROXIES`, so it cannot be spoofed; this feeds every IP-based fraud rule.
- JSON API bodies over 1 MB are refused (HTTP 413) without being read.
- Start-up prints plain-language warnings (no SMTP, no alert destination, no `ALLOWED_ORIGINS` / `TRUSTED_PROXIES`, CSP report-only, HSTS off).

**Verified:** unit tests (`logs/test_hardening.py`) and a live run in development and production mode, including a real HTTP alert delivered to a local Slack-style sink. **NOT verified:** a real email through a real SMTP server (a fake SMTP object was used), a real Slack workspace, the CSP in a real browser, or behaviour behind a real load balancer.

**Limits.** Rate-limit counters and alert de-duplication are in memory per process (use a shared store for several servers). Behind a proxy, rate limiting is only per real client IP if `TRUSTED_PROXIES` is set correctly. This does not replace a web firewall / CDN in front of the app.
