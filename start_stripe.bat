@echo off
cd /d "%~dp0"
rem ===== Stripe TEST MODE. Paste YOUR test keys below (Stripe dashboard > Developers > API keys, "Test mode" ON). =====
rem Never share the secret key (sk_test_...) or the webhook secret (whsec_...).
set STRIPE_PUBLISHABLE_KEY=pk_test_PASTE_HERE
set STRIPE_SECRET_KEY=sk_test_PASTE_HERE
rem Run  stripe listen --forward-to localhost:8080/api/stripe/webhook  in another window, then paste the whsec_ it prints:
set STRIPE_WEBHOOK_SECRET=whsec_PASTE_HERE
set PAYMENT_PROVIDER_MODE=stripe
set ENVIRONMENT=development
set ADMIN_PASSWORD=admin123
rem Cloudflare Turnstile TEST keys (always pass). Replace with real keys for real use.
set CAPTCHA_PROVIDER=turnstile
set TURNSTILE_SITE_KEY=1x00000000000000000000AA
set TURNSTILE_SECRET_KEY=1x0000000000000000000000000000000AA
rem Optional: ask for the human check one failed card before the block (needs internet). Remove "rem" to turn on.
rem set CAPTCHA_ON_CARD_FAILURES=1
echo Starting TradeVerify in STRIPE TEST MODE at http://localhost:8080  (Ctrl+C to stop)
python server.py
pause
