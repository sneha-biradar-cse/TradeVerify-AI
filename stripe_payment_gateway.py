"""Stripe test-mode payment adapter for TradeVerify AI.

The application never receives raw PAN/CVV. Stripe.js collects card details in
Stripe-hosted Elements and returns an opaque PaymentMethod ID. The server then
retrieves that PaymentMethod from Stripe, uses its provider fingerprint for the
TradeVerify fraud engine, and only confirms the PaymentIntent after the fraud
decision permits it.
"""
import os


class StripePaymentProviderError(RuntimeError):
    pass


def _secret_key():
    key = os.environ.get("STRIPE_SECRET_KEY", "").strip()
    if not key:
        raise StripePaymentProviderError("STRIPE_SECRET_KEY is not configured.")
    if not key.startswith("sk_test_"):
        raise StripePaymentProviderError("Stripe test mode requires a sk_test_ secret key.")
    return key


def _stripe_module():
    try:
        import stripe
    except ImportError as exc:
        raise StripePaymentProviderError('The stripe Python package is not installed. Run: python -m pip install -r requirements.txt') from exc
    return stripe

def _configure():
    s = _stripe_module()
    s.api_key = _secret_key()
    return s


def publishable_key():
    key = os.environ.get("STRIPE_PUBLISHABLE_KEY", "").strip()
    if not key:
        raise StripePaymentProviderError("STRIPE_PUBLISHABLE_KEY is not configured.")
    if not key.startswith("pk_test_"):
        raise StripePaymentProviderError("Stripe test mode requires a pk_test_ publishable key.")
    return key


def retrieve_payment_method(payment_method_id: str):
    s = _configure()
    try:
        pm = s.PaymentMethod.retrieve(payment_method_id)
    except Exception as exc:
        raise StripePaymentProviderError(f"Stripe PaymentMethod lookup failed: {exc}") from exc
    if getattr(pm, "livemode", True):
        raise StripePaymentProviderError("Live-mode PaymentMethods are not accepted by the test-mode adapter.")
    if getattr(pm, "type", "") != "card":
        raise StripePaymentProviderError("This TradeVerify checkout is configured for Stripe card payments in test mode.")
    card = getattr(pm, "card", None)
    fingerprint = getattr(card, "fingerprint", None) if card else None
    if not fingerprint:
        raise StripePaymentProviderError("Stripe did not return a card fingerprint for this PaymentMethod.")
    return pm, str(fingerprint)


def create_payment_intent(amount_minor: int, currency: str, invoice_ref: str,
                          account_id: str, session_id: str, idempotency_key: str):
    s = _configure()
    try:
        pi = s.PaymentIntent.create(
            amount=int(amount_minor),
            currency=currency.lower(),
            payment_method_types=["card"],
            confirmation_method="manual",
            capture_method="automatic",
            metadata={
                "tradeverify_invoice_ref": invoice_ref,
                "tradeverify_account_id": account_id,
                "tradeverify_session_id": session_id,
                "tradeverify_idempotency_key": idempotency_key,
                "tradeverify_environment": "test",
            },
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise StripePaymentProviderError(f"Stripe PaymentIntent creation failed: {exc}") from exc
    return pi


def attach_payment_method(payment_intent_id: str, payment_method_id: str,
                          fraud_decision: str, fraud_score: int):
    s = _configure()
    try:
        return s.PaymentIntent.modify(
            payment_intent_id,
            payment_method=payment_method_id,
            metadata={
                "tradeverify_fraud_decision": fraud_decision,
                "tradeverify_fraud_score": str(fraud_score),
                "tradeverify_payment_method_id": payment_method_id,
            },
        )
    except Exception as exc:
        raise StripePaymentProviderError(f"Stripe PaymentIntent update failed: {exc}") from exc


def confirm_payment_intent(payment_intent_id: str, force_step_up: bool = False):
    s = _configure()
    kwargs = {}
    if force_step_up:
        kwargs["payment_method_options"] = {"card": {"request_three_d_secure": "any"}}
    try:
        return s.PaymentIntent.confirm(payment_intent_id, **kwargs)
    except Exception as exc:
        raise StripePaymentProviderError(f"Stripe PaymentIntent confirmation failed: {exc}") from exc


def retrieve_payment_intent(payment_intent_id: str):
    s = _configure()
    try:
        return s.PaymentIntent.retrieve(payment_intent_id)
    except Exception as exc:
        raise StripePaymentProviderError(f"Stripe PaymentIntent lookup failed: {exc}") from exc


def cancel_payment_intent(payment_intent_id: str, reason: str = "fraudulent"):
    s = _configure()
    try:
        return s.PaymentIntent.cancel(payment_intent_id, cancellation_reason=reason)
    except Exception as exc:
        raise StripePaymentProviderError(f"Stripe PaymentIntent cancellation failed: {exc}") from exc


def verify_webhook(payload: bytes, signature: str):
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "").strip()
    if not secret:
        raise StripePaymentProviderError("STRIPE_WEBHOOK_SECRET is not configured.")
    s = _configure()
    try:
        return s.Webhook.construct_event(payload, signature, secret)
    except Exception as exc:
        raise StripePaymentProviderError(f"Stripe webhook signature verification failed: {exc}") from exc
