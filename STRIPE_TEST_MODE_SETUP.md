# TradeVerify AI v5 — Stripe test mode

## 1. Install
```powershell
pip install -r requirements.txt
```

## 2. Configure `.env`
Copy `.env.example` to `.env` and set your own Stripe **test-mode** keys:
```text
PAYMENT_PROVIDER_MODE=stripe
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
INVOICE_CATALOG_FILE=invoices.json
PAYMENT_LEDGER_FILE=payment_ledger.json
```
Never share `sk_test_...` or `whsec_...`.

## 3. Load environment variables in PowerShell
```powershell
$env:STRIPE_PUBLISHABLE_KEY = "pk_test_YOUR_KEY"
$env:STRIPE_SECRET_KEY = "sk_test_YOUR_KEY"
$env:STRIPE_WEBHOOK_SECRET = "whsec_YOUR_SECRET"
$env:PAYMENT_PROVIDER_MODE = "stripe"
$env:ENVIRONMENT = "development"
$env:INVOICE_CATALOG_FILE = "invoices.json"
```

## 4. Start
```powershell
python server.py
```

## 5. Webhook
Install the Stripe CLI, sign in to your Stripe test account, then run:
```powershell
stripe listen --forward-to localhost:8080/api/stripe/webhook
```
Copy the displayed `whsec_...` into `STRIPE_WEBHOOK_SECRET` and restart the server.

## 6. Test the normal customer flow
Open the dashboard, choose **Pay Invoice**, enter the invoice reference from `invoices.json`, and use Stripe's official test cards. The card fields are hosted by Stripe. TradeVerify receives only an opaque PaymentMethod ID/fingerprint.

The flow is:
1. Server creates a PaymentIntent from the invoice catalog.
2. Stripe.js collects card details.
3. Server retrieves the Stripe PaymentMethod/fingerprint.
4. TradeVerify evaluates carding + bot risk.
5. If allowed, server confirms the PaymentIntent.
6. If Stripe requests 3DS, the browser handles the authentication and the server completes confirmation.
7. Stripe webhook records the final payment event.

## 7. Fraud test drawer
The existing admin/developer fraud test drawer remains a controlled simulation harness. It is not part of the customer payment flow. For production, set `ENVIRONMENT=production`; the harness is then disabled automatically.


### v6 fraud-flow behavior
1. Customer enters card details in Stripe-hosted Elements.
2. TradeVerify records an attempt with unknown provider outcome (`success=None`) and evaluates existing Problem 3/4 signals.
3. A blocked attempt is stopped before Stripe authorization.
4. An allowed attempt is attached/confirmed in Stripe.
5. Stripe's actual success/failure is then recorded as the authoritative payment outcome.
6. Repeated real test declines therefore accumulate in the Problem 3 failure windows without counting the pre-check as a success.


## Development-only local payment testing

If the client payment gateway is not known yet, set `PAYMENT_PROVIDER_MODE=local_test` (or leave the mode unset while `ENVIRONMENT=development`). The customer payment drawer then shows local test card fields. The browser derives an opaque fingerprint and token; raw card number/CVV are not sent to the TradeVerify server. This adapter does not contact Stripe or any bank and must not be used in production.

Suggested local tests:
- Success: `4242 4242 4242 4242`, any future MM/YY, 3-digit CVV.
- Decline A: `4000 0000 0000 0002`.
- Decline B: `4000 0000 0000 0101`.
- Decline C: `4000 0000 0000 0200`.

Use the same decline card three times within five minutes to trigger the same-payment-method carding rule. Use different decline cards within two minutes to exercise the distinct-payment-method rule. For bot-speed testing, the internal development harness still uses the same fraud engine because a human cannot reliably generate sub-800ms attempts.
