# TradeVerify AI — Production Payment Fraud Controls (Problems 3 & 4)

## Scope
This release focuses on:
- **Problem 3:** back-to-back payment failures / card testing (carding)
- **Problem 4:** rapid automated billing/payment attempts (bot-speed abuse)

The rules are externalized in `fraud_policy.json`. The application code does not contain the fraud thresholds or risk weights.

> The policy values in this repository are engineering starting points for a prototype. They are **not FedEx policy** and must be tuned and validated with real transaction data before production use.

## Production flow

`Customer checkout -> payment provider tokenization -> payment authorization -> TradeVerify fraud engine -> ALLOW / STEP_UP_REQUIRED / REVIEW / BLOCK`

The fraud service accepts only an opaque payment-method token/fingerprint. It rejects raw PAN/card number/CVV fields.

## Problem 3 — card testing / carding

The engine evaluates several dimensions instead of relying on one rule:
- repeated failures on the same payment-method fingerprint
- multiple distinct payment methods in a short window
- failure bursts within a short window
- session/account/IP velocity state
- an existing account/session fraud block

When a high-confidence card-testing condition fires, the affected payment session and authenticated account can be frozen for the configured duration. Alerts are emitted through the existing alert engine.

## Problem 4 — bot-speed / rapid automation

The engine measures:
- time between payment attempts
- repeated rapid-payment strikes in a rolling window
- short-window payment-attempt bursts
- network-address changes observed within a checkout session

The engine does not depend on user-agent strings alone or on a customer-facing simulation button.

## Common risk decision

Carding and bot signals feed one configurable risk score. The decision policy supports:
- `ALLOW`
- `STEP_UP_REQUIRED`
- `REVIEW`
- `BLOCK`

A `STEP_UP_REQUIRED` or `REVIEW` result does not mark the simulated payment as paid. A real provider integration should map this state to an appropriate additional verification flow such as provider-supported 3DS/risk review.

## State and scaling

Redis is supported for shared velocity state. For a multi-instance production deployment, set `REDIS_URL` and verify connectivity. The in-memory store remains useful for local development but is not suitable for horizontally scaled production.

## Payment gateway boundary

`payment_gateway.py` provides a provider boundary and a local simulated provider. The current ZIP intentionally does **not** claim to process real FedEx payments or real card charges.

For production, connect a PCI-compliant provider using its hosted/tokenized payment fields. The provider should return the opaque payment-method token/fingerprint and authorization result to the server-side fraud flow. Do not send raw card data to TradeVerify.

## Customer vs test UI

The normal `checkout.html` flow contains only the customer payment action. Attack simulation controls were removed from that page. `fraud-test.html` is a separate developer/test page for controlled verification of Problems 3 and 4.

## Remaining production work outside this fraud-rule implementation

1. Connect a real payment provider in its sandbox/test environment, then production after validation.
2. Put Redis behind the production network/security controls and test failover.
3. Move accounts, OTP/session state and audit records from process memory to a real database/shared session store.
4. Put the HTTP service behind TLS termination and a production process manager/reverse proxy.
5. Load/soak test concurrent payment attempts and verify state isolation between accounts.
6. Tune thresholds using representative transaction data and monitor false-positive/false-negative rates.
7. Add operational review, rollback/override controls, audit retention and incident-response procedures.
8. Use a secrets manager for all API keys, database credentials and provider secrets.


## v5 — Stripe test-mode checkout

The normal payment drawer now uses Stripe-hosted card fields in test mode. The browser never sends raw card data to TradeVerify. The server creates the PaymentIntent from the server-side invoice catalog, retrieves the Stripe PaymentMethod and provider fingerprint, runs the TradeVerify fraud gate, and only then confirms the PaymentIntent. Stripe webhooks are used to observe final payment success/failure.

### Required environment
- `PAYMENT_PROVIDER_MODE=stripe`
- `STRIPE_PUBLISHABLE_KEY=pk_test_...`
- `STRIPE_SECRET_KEY=sk_test_...`
- `STRIPE_WEBHOOK_SECRET=whsec_...`
- `INVOICE_CATALOG_FILE=invoices.json`

Use Stripe test mode only for this build. Do not paste secret keys into source code or chat.

### Local webhook testing
Use the Stripe CLI to forward Stripe events to `http://localhost:8080/api/stripe/webhook`, then copy the CLI webhook signing secret into `STRIPE_WEBHOOK_SECRET`.

### Important
v5 is a real Stripe test-mode integration, not a production live-payment deployment. Production still requires live provider credentials, public HTTPS webhook infrastructure, persistent shared fraud state (Redis/database), secret management, TLS/reverse proxy, monitoring, load testing, PCI/compliance review, and operational controls.


## v6 payment-flow correction
- Customer payment attempts are recorded before provider authorization without being marked successful.
- The provider result is the authoritative success/failure outcome and is recorded from the Stripe result/webhook.
- Pre-authorization timing/card-method signals therefore do not manufacture payment successes or failures.
- Customer-facing dashboard no longer exposes the developer Fraud Test Controls; the controlled harness remains development-only.


### Local payment test mode
The local test provider is strictly for development validation of Problems 3 and 4. It does not process real payments and must be disabled in production.


## Local test provider v8
The local development provider accepts arbitrary card-like test numbers and uses LOCAL_TEST_PROVIDER_OUTCOME=authorized|declined to control the simulated provider result. No card number is hard-coded. This provider must never be used for production or represented as real card authorization.
