# v35e: wiring audit - backend features that had no front end

I listed every backend API route (42) and checked which ones any page calls. 34 are used. These gaps were in the payment / fraud area and are now connected:

1. **"Ask for extra proof" now does something in local test mode.** The risk score could say "step-up required", but only the Stripe path acted on it (it forces 3-D Secure). The local flow ignored it. Now the payment is held (HTTP 428) until the person passes the human check; one pass releases exactly one payment; wrong answers keep it held; ordinary customers are never asked. Needs the Turnstile keys (switch off with `STEPUP_CHECK=0`). The page shows the check box and asks the customer to press Pay again.
2. **Admin page "System status" panel** (`GET /api/admin/system-status`): is login-code delivery on (email / SMS / WhatsApp), block alerts, CAPTCHA (and whether it uses Cloudflare TEST keys), extra checks, rate limits, shared counters. Never shows a secret.
3. **Admin page "Send test" button** (`POST /api/admin/test-message`): sends one clearly-labelled test email / SMS / WhatsApp, admin password required, 5 per 5 minutes, written to the audit log. This is the same check as `check_otp_delivery.py`, from the browser.

## Backend routes with no page calling them (left alone on purpose)
* `/api/stripe/webhook`: Stripe calls it, not a page. Correct.
* `/api/scout/payment-attempt-checkout`: a development simulation endpoint.
* `/api/upload`, `/api/process_batch`: no page uses them (the document pages call `/extract-document`); look like old endpoints.
* `/api/export_contact`, `/api/exporter/holds`, `/api/exporter/hold-status`: **Problem 2** (regulatory notice and terminal hold). They work as APIs but no screen sends a notice or looks up a hold. Not part of Problems 3 and 4, so not built here; say if you want a screen for them.

## Tests
`logs/test_stepup_and_status.py` (new) plus all earlier suites pass. Stand-ins are used for Cloudflare, Twilio and the mail server; not verified against the real services, a browser, or real SMS delivery rules in India.
