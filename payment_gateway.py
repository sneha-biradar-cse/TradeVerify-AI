"""Payment provider boundary.

The fraud engine never needs raw card data. In production the checkout page must
use the payment provider's hosted/tokenized fields and send only an opaque
payment method token plus provider-supplied fingerprint to this application.
"""
import hashlib
import os

from fraud_policy import POLICY


class PaymentProviderError(RuntimeError):
    pass


class SimulatedPaymentProvider:
    """Local test provider with all behavior controlled by policy/config."""
    def authorize(self, payment_method_token: str, amount: str = '', currency: str = 'USD',
                  idempotency_key: str = '', simulation_outcome: str = '') -> dict:
        token = (payment_method_token or '').strip()
        if not token.startswith('demo_pm_'):
            raise PaymentProviderError('Simulated provider accepts only opaque demo payment-method tokens.')

        cfg = POLICY.get('payment_simulation', {})
        default_outcome = str(cfg.get('default_outcome', 'authorized')).strip().lower()
        allowed = {str(v).strip().lower() for v in cfg.get('allowed_test_outcomes', [])}
        allow_test = bool(cfg.get('allow_test_outcome', False)) and os.environ.get('PAYMENT_SIMULATION_ALLOW_TEST_OUTCOME', 'true').strip().lower() == 'true'

        outcome = default_outcome
        requested = (simulation_outcome or '').strip().lower()
        if requested:
            if not allow_test or requested not in allowed:
                raise PaymentProviderError('Controlled payment simulation outcome is not enabled.')
            outcome = requested

        if outcome not in allowed and outcome != 'authorized':
            raise PaymentProviderError('Unsupported simulated payment outcome in fraud policy.')

        success = outcome == 'authorized'
        return {
            'success': success,
            'provider': 'simulated',
            'authorization_id': 'sim_' + hashlib.sha256((idempotency_key or token).encode()).hexdigest()[:24],
            'decline_code': None if success else 'card_declined'
        }


def get_payment_provider():
    mode = os.environ.get('PAYMENT_PROVIDER_MODE', 'simulated').strip().lower()
    if mode == 'simulated':
        return SimulatedPaymentProvider()
    raise PaymentProviderError(
        f"Unsupported PAYMENT_PROVIDER_MODE '{mode}'. Configure a real payment-provider adapter before production."
    )
