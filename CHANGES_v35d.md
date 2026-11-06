# v35d: login codes by email / SMS / WhatsApp, and three extra fraud protections

Built on v35c. Everything that worked before is unchanged; these are additions.

## A. The login code now reaches the customer (no more terminal)

* `otp_settings.env` (new): fill in your email and/or Twilio details, restart. Keep the file private (it holds secrets).
* **Email**: any SMTP mail account (Gmail App Password, Office 365, SendGrid / Amazon SES SMTP).
* **SMS** and **WhatsApp**: through Twilio's REST API (no extra library). `OTP_CHANNELS=email,sms,whatsapp` picks the channels; a code goes to every listed channel that is configured AND that the user gave at sign-up. The same 6-digit code arrives on each.
* **Sign-up** now asks for an optional mobile number (with or without country code; `DEFAULT_PHONE_COUNTRY_CODE=+91`). With delivery set up, sign-up needs an email or a mobile number.
* **Login page** says where the code went (`r***@gmail.com`, `+91********10`), never shows the code, and has a **Resend code** button (30 s apart, 3 times; a resend makes a NEW code and the old one stops working; wrong-code attempts are not reset).
* **The unblock code** (self-unlock after a fraud lock) uses the same channels.
* **Bill protection**: at most 3 SMS per number per hour (`OTP_MAX_SMS_PER_NUMBER_PER_HOUR`), 10 emails per address per hour, rate limit on the resend endpoint. One failing channel never stops the others or the login.
* **Safe by default**: production never returns or logs a code; if nothing can be delivered, login is refused. Development shows the TEST code on screen only when `SHOW_DEV_HINTS=1`, otherwise only in the server window.
* The two seeded demo accounts use fake `@example.com` addresses; nothing is sent to them (they keep using the test code in development). Set `DEMO_EXPORTER_EMAIL` / `DEMO_EXPORTER_PHONE` (and the importer ones) to receive their codes yourself.
* `python check_otp_delivery.py email you@gmail.com` (or `sms +91...`, `whatsapp +91...`, `status`) sends ONE test message and explains failures.
* New files: `otp_delivery.py`, `env_loader.py`, `otp_settings.env`, `check_otp_delivery.py`. Changed: `auth_engine.py`, `account_unlock.py`, `server.py`, both login pages, `fraud_policy.json` (rate limit for resend), `start.bat`.

## B. Three extra fraud protections (`extra_signals.py`, settings in `fraud_policy.json` -> `extra_signals`)

Each adds points to the SAME risk score as the existing rules (below 30 allow, 30-59 ask for extra proof, 60-79 review, 80+ block), so none blocks by itself.

1. **Device ID**: the browser keeps a random id (`tv_device_id`). 5 different cards from one device in 10 min = +35; 3 different accounts on one device in 1 h = +40. A fraudster can clear it (private window), so it is a hint only. It is personal data: declare it in your privacy notice.
2. **Same card family**: 4 different cards sharing the first 6 digits in 10 min = +30 (per account or per device). If a gateway does not give the digits, a weaker stand-in (brand + country + card type) needs 6 cards and adds only +15.
3. **Security code / postcode result**: "no match" adds +25 each; "unavailable" or "not checked" adds nothing. Local test mode simulates the network's answer (security code `000` or postcode `00000` = no match; the form has a new optional postcode box). With Stripe the answer is read from the payment method's `card.checks` after the attempt (webhook).

If the extra points are what push a score to BLOCK, it becomes a normal fraud block: reference ID, escalating lock, alert, admin page, self-unlock.

## Verified, and not verified

* Verified: every payment / fraud / hardening test file passes (see `logs/`), plus new `logs/test_extra_signals.py` and `logs/test_otp_delivery.py`. The delivery test runs the REAL server against a local mail server (STARTTLS + login) and a local stand-in for Twilio. A live run through the real server confirmed device (3rd account +40 = step-up), card family (4th card +30), code/postcode (both no-match +50 = review; code only +25 = a typo is not blocked; unavailable = +0) and a combined BLOCK with reference ID on the admin page.
* NOT verified: real Gmail / Twilio (run `check_otp_delivery.py` with your own keys), SMS delivery rules for India (TRAI DLT registration is needed to text real customers), Stripe's real `card.checks` and card-digit fields, WhatsApp beyond Twilio's sandbox.
* The PCI-style note: the page now also sends the card's first 6 and last 4 digits (not enough to make a payment) and the device id.
* Five document-checking tests (`test_ais_verification`, `test_authenticity`, `test_local_extractor`, `test_real_img`, `test_sanctions_engine`) already fail in your original v35c zip; they are unrelated to payments and were not touched.
