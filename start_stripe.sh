#!/bin/bash
cd "$(dirname "$0")"
# ===== Stripe TEST MODE. Paste YOUR test keys (Stripe dashboard > Developers > API keys, Test mode ON). =====
# Never share the secret key (sk_test_...) or the webhook secret (whsec_...).
export STRIPE_PUBLISHABLE_KEY=pk_test_PASTE_HERE
export STRIPE_SECRET_KEY=sk_test_PASTE_HERE
# In another window run: stripe listen --forward-to localhost:8080/api/stripe/webhook   then paste the whsec_ it prints:
export STRIPE_WEBHOOK_SECRET=whsec_PASTE_HERE
export PAYMENT_PROVIDER_MODE=stripe ENVIRONMENT=development ADMIN_PASSWORD=admin123
# Cloudflare Turnstile TEST keys (always pass). Replace with real keys for real use.
export CAPTCHA_PROVIDER=turnstile TURNSTILE_SITE_KEY=1x00000000000000000000AA TURNSTILE_SECRET_KEY=1x0000000000000000000000000000000AA
# export CAPTCHA_ON_CARD_FAILURES=1
echo "Starting TradeVerify in STRIPE TEST MODE at http://localhost:8080  (Ctrl+C to stop)"
python3 server.py
