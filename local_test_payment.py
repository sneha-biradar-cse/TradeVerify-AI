"""Development-only local payment provider for TradeVerify fraud-flow testing.

This provider accepts arbitrary card-like test numbers in development mode.
It does not contact a payment network and cannot determine whether a real card
is genuine. Provider outcomes are selected by environment configuration, not
by hard-coded card numbers.
"""
import hashlib
import os

class LocalTestPaymentError(RuntimeError):
    pass

def configured_outcome():
    outcome = os.environ.get('LOCAL_TEST_PROVIDER_OUTCOME', 'authorized').strip().lower()
    if outcome not in ('authorized', 'declined', 'by_card', 'approve_by_card'):
        raise LocalTestPaymentError("LOCAL_TEST_PROVIDER_OUTCOME must be 'authorized', 'declined', 'by_card' or 'approve_by_card'.")
    return outcome

def decline_suffixes():
    """by_card mode: cards whose LAST 4 digits are listed here are declined; every other card is approved.
    Set LOCAL_TEST_DECLINE_SUFFIXES (comma separated, default '0002')."""
    raw = os.environ.get('LOCAL_TEST_DECLINE_SUFFIXES', '0002')
    return [x.strip() for x in raw.split(',') if x.strip().isdigit() and len(x.strip()) == 4]

def approve_suffixes():
    """approve_by_card mode (the reverse of by_card): ONLY cards whose last 4 digits are listed here are
    approved; every other card is declined. Set LOCAL_TEST_APPROVE_SUFFIXES (comma separated, default '0002')."""
    raw = os.environ.get('LOCAL_TEST_APPROVE_SUFFIXES', '0002')
    return [x.strip() for x in raw.split(',') if x.strip().isdigit() and len(x.strip()) == 4]

def config_for_browser():
    outcome = configured_outcome()
    return {
        'mode': 'local_test',
        'warning': 'DEVELOPMENT TEST PROVIDER — no real payment is processed.',
        'provider_outcome': outcome,
        'decline_suffixes': decline_suffixes() if outcome == 'by_card' else [],
        'approve_suffixes': approve_suffixes() if outcome == 'approve_by_card' else [],
        'accepts_arbitrary_cards': True,
        'test_lab': os.environ.get('ENABLE_TEST_LAB', '0').strip() == '1',
    }

def make_fingerprint(card_number: str) -> str:
    digits = ''.join(ch for ch in str(card_number or '') if ch.isdigit())
    if len(digits) < 12 or len(digits) > 19:
        raise LocalTestPaymentError('Card number must contain 12–19 digits.')
    return 'local_fp_' + hashlib.sha256(digits.encode()).hexdigest()[:32]

def make_token(fingerprint: str) -> str:
    return 'local_pm_' + fingerprint.replace('local_fp_', '')

def authorize(payment_method_token: str, payment_method_fingerprint: str, idempotency_key: str = '', card_last4: str = '') -> dict:
    if not str(payment_method_token or '').startswith('local_pm_'):
        raise LocalTestPaymentError('Local test provider requires an opaque local payment-method token.')
    if not str(payment_method_fingerprint or '').startswith('local_fp_'):
        raise LocalTestPaymentError('Local test provider requires a local payment fingerprint.')
    outcome = configured_outcome()
    if outcome == 'by_card':
        # Only the last 4 digits are used (never the full number); the browser sends just those.
        outcome = 'declined' if str(card_last4 or '') in decline_suffixes() else 'authorized'
    elif outcome == 'approve_by_card':
        # Reverse of by_card: only the listed last-4 suffixes are approved, everything else is declined.
        outcome = 'authorized' if str(card_last4 or '') in approve_suffixes() else 'declined'
    digest = hashlib.sha256((idempotency_key or payment_method_token).encode()).hexdigest()[:24]
    return {
        'success': outcome == 'authorized',
        'provider': 'local_test',
        'authorization_id': 'local_' + digest,
        'decline_code': None if outcome == 'authorized' else 'configured_test_decline',
        'test_mode': True,
    }
