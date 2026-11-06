# TradeVerify v7 — Local Customer Payment Fraud Test

## Purpose

Use this guide when the client's real payment gateway is not known yet. It lets you test Problems 3 and 4 through the normal customer payment screen without a Stripe account.

**This is a development test provider. It does not move real money and must not be used in production.**

## 1. Start local test mode

Open PowerShell in `doc verification(Export)` and run:

```powershell
$env:PAYMENT_PROVIDER_MODE="local_test"
$env:ENVIRONMENT="development"
python server.py
```

If you previously set Stripe mode in the same PowerShell, the `PAYMENT_PROVIDER_MODE="local_test"` line overrides it for that terminal.

## 2. Open the application

Open:

```text
http://localhost:8080
```

Log in normally and open:

**Exporter Dashboard → Invoice & Payment → Pay Invoice**

You should see:

- Card number
- Expiry
- CVV
- Pay Securely
- A yellow development-test note

The application does not send raw card number/CVV to the TradeVerify server in this mode.

## 3. Test a normal successful payment

Start the server with the local provider configured to authorize: 

```powershell
$env:LOCAL_TEST_PROVIDER_OUTCOME="authorized"
python server.py
```

Enter **any 12–19 digit card-like test number** that passes the on-screen validation, any future expiry, and a 3–4 digit CVV. If TradeVerify does not detect a fraud condition, the result is:

```text
Payment successful — TradeVerify allowed the transaction.
```

This is a local simulation; it does not prove the card is genuine. Only a real payment provider can perform real authorization.

## 4. Problem 3 — same payment method failures

Restart the development server with the provider configured to decline: 

```powershell
$env:LOCAL_TEST_PROVIDER_OUTCOME="declined"
python server.py
```

Use the **same arbitrary card-like number** three times. No specific card number is required or hard-coded.

Expected sequence:

```text
Attempt 1 → provider decline → failure recorded
Attempt 2 → provider decline → failure recorded
Attempt 3 → provider decline → CARDING_RED_FLAG / session protection
```



Use this decline card three times:

```text
4000 0000 0000 0002
```

Use a future expiry and a 3-digit CVV each time.

Expected sequence:

```text
Attempt 1 → declined → failure recorded
Attempt 2 → declined → failure recorded
Attempt 3 → declined → CARDING_RED_FLAG / session protection activated
```

The important state is that the **same payment fingerprint** is used for all three attempts.

## 5. Problem 3 — different payment methods

Keep `LOCAL_TEST_PROVIDER_OUTCOME="declined"`. Enter four different card-like test numbers within two minutes. For example, use four different 16-digit values of your choice. The application derives a different opaque fingerprint for each number; no card numbers are stored in configuration.

Expected result when the configured threshold is reached:

```text
CARDING_RED_FLAG
Payment blocked / payment session suspended
```

## 6. Problem 3 — five-attempt burst

Use five configured decline cards/attempts in less than 30 seconds.

Expected result:

```text
CARDING_RED_FLAG
Failed-attempt burst threshold reached
```

## 7. Problem 4 — rapid automated billing

A human typing a card normally will not reliably create sub-800ms attempts. For this reason, the internal development bot-speed harness remains available for controlled velocity testing. It uses the same `record_transaction_event()` fraud engine used by the customer payment path.

Expected behavior:

```text
rapid attempt → SUSPECT / strike
rapid attempt → SUSPECT / strike
rapid attempt → BOT_RED_FLAG at configured threshold
```

## 8. What to show your mentor/client

Accurate statement:

> “I integrated Problems 3 and 4 into the normal payment workflow and validated the fraud engine locally through the customer payment interface. The development provider is intentionally isolated from the real payment network. The final provider adapter will be connected after the client's actual payment gateway is confirmed.”

Do not describe the local test provider as a real Stripe transaction.

## v9 fix
The local test provider outcome is controlled only by the server environment (`LOCAL_TEST_PROVIDER_OUTCOME`) and is no longer accepted from the browser. This prevents a client from choosing its own provider result. Card numbers are arbitrary test inputs and are fingerprinted; no specific card number determines authorization.
