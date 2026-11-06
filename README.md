# TradeVerify AI
Trade-document verification and payment-fraud-protection prototype.

## Setup
1. `pip install -r requirements.txt`
2. `cp .env.example .env` and fill in your own keys (never commit `.env`)
3. `cp otp_settings.env.example otp_settings.env` and fill in email/Twilio if you want real login codes
4. Run `start.sh` (Linux/Mac) or `start.bat` (Windows)

See `PRODUCTION_READINESS.md`, `STRIPE_TEST_MODE_SETUP.md` and the `CHANGES_*.md` files for details.
