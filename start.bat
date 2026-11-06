@echo off
cd /d "%~dp0"
set ENVIRONMENT=development
set PAYMENT_PROVIDER_MODE=local_test
set LOCAL_TEST_PROVIDER_OUTCOME=approve_by_card
set ADMIN_PASSWORD=admin123
set CAPTCHA_PROVIDER=turnstile
set TURNSTILE_SITE_KEY=1x00000000000000000000AA
set TURNSTILE_SECRET_KEY=1x0000000000000000000000000000000AA
rem --- Presentation mode: the login code is NOT shown on the page. Without email it appears only in THIS window (the server console).
rem     Set SHOW_DEV_HINTS=1 to bring the on-screen code and demo hint back for development.
set SHOW_DEV_HINTS=0
rem --- To get the login code by REAL EMAIL instead (best for a demo), remove "rem" from the 5 lines below and fill them in.
rem     Gmail needs 2-Step Verification and an "App password" (Google Account > Security > App passwords), not your normal password.
rem set SMTP_HOST=smtp.gmail.com
rem set SMTP_PORT=587
rem set SMTP_USER=youraddress@gmail.com
rem set SMTP_PASSWORD=your16characterapppassword
rem set DEMO_EXPORTER_EMAIL=youraddress@gmail.com
rem set DEMO_IMPORTER_EMAIL=youraddress@gmail.com
echo Starting TradeVerify at http://localhost:8080  (Ctrl+C to stop)
rem Optional alerts: tell a human when an account is blocked. Remove "rem" and fill in.
rem set ALERT_WEBHOOK_URL=https://hooks.slack.com/services/PASTE_HERE
rem set ALERT_EMAIL_TO=security@yourcompany.com
rem set PUBLIC_BASE_URL=http://localhost:8080
rem Optional: email the one-time codes (Gmail needs an App Password). Without these, codes show on screen in development.
rem set SMTP_HOST=smtp.gmail.com
rem set SMTP_USER=you@gmail.com
rem set SMTP_PASSWORD=PASTE_APP_PASSWORD
rem Optional: ask for the human check one failed card before the block (needs internet). Remove "rem" to turn on.
rem set CAPTCHA_ON_CARD_FAILURES=1
rem Login codes by email / SMS / WhatsApp: fill in otp_settings.env (no need to edit this file).
python server.py
pause
