#!/bin/bash
cd "$(dirname "$0")"
export ENVIRONMENT=development PAYMENT_PROVIDER_MODE=local_test LOCAL_TEST_PROVIDER_OUTCOME=approve_by_card ADMIN_PASSWORD=admin123 CAPTCHA_PROVIDER=turnstile TURNSTILE_SITE_KEY=1x00000000000000000000AA TURNSTILE_SECRET_KEY=1x0000000000000000000000000000000AA
# --- Presentation mode: the login code is NOT shown on the page. Without email it appears only in this terminal.
#     Set SHOW_DEV_HINTS=1 to bring the on-screen code and demo hint back for development.
export SHOW_DEV_HINTS=0
# --- To get the login code by REAL EMAIL instead (best for a demo), uncomment and fill in. Gmail needs an App password.
# export SMTP_HOST=smtp.gmail.com SMTP_PORT=587 SMTP_USER=youraddress@gmail.com SMTP_PASSWORD=your16characterapppassword
# export DEMO_EXPORTER_EMAIL=youraddress@gmail.com DEMO_IMPORTER_EMAIL=youraddress@gmail.com
echo "Starting TradeVerify at http://localhost:8080  (Ctrl+C to stop)"
python3 server.py
