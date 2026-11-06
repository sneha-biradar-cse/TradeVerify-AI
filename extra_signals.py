"""
Three extra protections for Problems 3 and 4. They are ADDITIONS: each one adds points to the same risk score the
existing rules use (fraud_policy.json -> risk_scoring decisions: <30 allow, 30-59 step-up, 60-79 review, 80+ block),
so no single protection blocks anyone by itself. Settings: fraud_policy.json -> "extra_signals".

 1. DEVICE ID    the browser keeps a random id. Many different cards, or many different accounts, on one device add points.
                 It is a hint, not proof: a fraudster can clear it (private window), so it only helps score the rest.
 2. CARD FAMILY  the first 6 digits of a card say which bank / card type it is. Several different cards from one family
                 in a short time add points (guessed card numbers). Without those digits (some gateways do not give
                 them) a weaker stand-in is used: card brand + country + funding type, with a higher bar and fewer points.
 3. CVC / POSTCODE RESULT  the card network answers "match / no match" for the security code and the billing postcode.
                 "No match" adds points; "unavailable" or "not checked" adds NOTHING (many countries never answer).

Personal-data note: a device id and the first 6 digits of a card are data you must declare in your privacy notice.
"""
import re
import time

import account_scout as _S

_CFG = _S.POLICY.get('extra_signals') or {}
_DEVICE_RE = re.compile(r'^[A-Za-z0-9_-]{16,64}$')


def enabled():
    return bool(_CFG.get('enabled', True))


def clean_device_id(value):
    """Only a well-formed random id is accepted; anything else counts as 'no device id'."""
    return value if isinstance(value, str) and _DEVICE_RE.match(value) else ''


def clean_bin(value):
    """First 6 digits of a card number, or '' when fewer than 6 digits are available."""
    digits = ''.join(ch for ch in str(value or '') if ch.isdigit())
    return digits[:6] if len(digits) >= 6 else ''


def norm_check(value):
    """The card network's answer, reduced to pass / fail / unavailable / unchecked."""
    v = str(value or '').strip().lower()
    if v in ('pass', 'fail', 'unavailable', 'unchecked'):
        return v
    return 'unchecked' if not v else 'unavailable'


def _family(bin6, brand, country, funding):
    if bin6:
        return 'bin', 'bin:' + bin6
    if brand or country or funding:
        return 'weak', 'weak:' + '|'.join(str(x or '').lower() for x in (brand, country, funding))
    return '', ''


def evaluate_attempt(account_id, device_id, card_fp, bin6='', brand='', country='', funding='', now=None):
    """
    Called once per payment attempt (before the card is charged). Records who/what was seen and returns
    {'points': int, 'reasons': [...], 'signals': {...}}. Counting uses the same store as the existing rules
    (memory, or Redis when REDIS_URL is set).
    """
    out = {'points': 0, 'reasons': [], 'signals': {}}
    if not enabled() or not card_fp:
        return out
    now = now if now is not None else time.time()
    store = _S._STORE
    device_id = clean_device_id(device_id)
    bin6 = clean_bin(bin6)
    dev = _CFG.get('device') or {}
    fam = _CFG.get('card_family') or {}

    if device_id:
        c = dev.get('cards') or {}
        n = store.sliding_distinct_count(f'xs_dev_cards:{device_id}', now, card_fp, c.get('window_seconds', 600))
        out['signals']['device_cards'] = n
        if n >= c.get('count', 5):
            out['points'] += c.get('points', 35)
            out['reasons'].append(f'{n} different cards tried from one device')
        if account_id:
            a = dev.get('accounts') or {}
            m = store.sliding_distinct_count(f'xs_dev_accts:{device_id}', now, account_id, a.get('window_seconds', 3600))
            out['signals']['device_accounts'] = m
            if m >= a.get('count', 3):
                out['points'] += a.get('points', 40)
                out['reasons'].append(f'{m} different accounts used from one device')

    kind, fam_id = _family(bin6, brand, country, funding)
    if kind:
        cfg = fam.get(kind) or {}
        owners = [('acct', account_id)] + ([('dev', device_id)] if device_id else [])
        worst = 0
        for tag, owner in owners:
            if owner:
                worst = max(worst, store.sliding_distinct_count(f'xs_fam_{tag}:{owner}:{fam_id}', now, card_fp, cfg.get('window_seconds', 600)))
        out['signals']['card_family'] = {'kind': kind, 'distinct_cards': worst}
        if worst >= cfg.get('count', 4):
            out['points'] += cfg.get('points', 30)
            out['reasons'].append(f'{worst} different cards from the same card family' + ('' if kind == 'bin' else ' (brand/country/type, weaker signal)'))
    return out


def evaluate_checks(cvc, postcode):
    """After the card network has answered. Only a clear 'fail' adds points."""
    cfg = _CFG.get('checks') or {}
    out = {'points': 0, 'reasons': [], 'signals': {'cvc_check': norm_check(cvc), 'postcode_check': norm_check(postcode)}}
    if not enabled():
        return out
    if out['signals']['cvc_check'] == 'fail':
        out['points'] += cfg.get('cvc_fail_points', 25)
        out['reasons'].append('security code did not match')
    if out['signals']['postcode_check'] == 'fail':
        out['points'] += cfg.get('postcode_fail_points', 25)
        out['reasons'].append('billing postcode did not match')
    return out


def checks_from_stripe_pm(pm):
    """cvc / postcode results from a Stripe PaymentMethod (card.checks). Missing data = 'unchecked' (adds nothing)."""
    card = getattr(pm, 'card', None)
    checks = (card.get('checks') if isinstance(card, dict) else getattr(card, 'checks', None)) if card else None
    def get(name):
        if checks is None:
            return None
        return checks.get(name) if isinstance(checks, dict) else getattr(checks, name, None)
    return get('cvc_check'), get('address_postal_code_check')


def card_info_from_stripe_pm(pm):
    """brand / country / funding / first digits (when Stripe gives them) from a Stripe PaymentMethod."""
    card = getattr(pm, 'card', None)
    def get(name):
        if card is None:
            return ''
        return (card.get(name) if isinstance(card, dict) else getattr(card, name, '')) or ''
    return {'brand': get('brand'), 'country': get('country'), 'funding': get('funding'), 'bin6': clean_bin(get('iin'))}


def merge(*parts):
    """Adds several evaluation results together."""
    out = {'points': 0, 'reasons': [], 'signals': {}}
    for p in parts:
        if p:
            out['points'] += int(p.get('points', 0))
            out['reasons'] += list(p.get('reasons', []))
            out['signals'].update(p.get('signals', {}))
    return out


def apply_to_risk(risk, extras):
    """The existing risk result plus the extra points; the decision is recomputed with the SAME bands."""
    if not extras or not extras.get('points'):
        return risk
    out = dict(risk)
    out['score'] = risk.get('score', 0) + extras['points']
    out['reasons'] = list(risk.get('reasons', [])) + list(extras['reasons'])
    out['decision'] = _S._risk_decision(out['score'])
    out['extra_signal_points'] = extras['points']
    out['extra_signals'] = extras['signals']
    out['details'] = f"Payment risk score {out['score']}: {out['decision']}. " + '; '.join(out['reasons'])
    return out


def block_if_needed(risk_before, risk_after, extras, account_id, session_id, now=None):
    """
    If the extra points are what pushed the score into BLOCK, make it a normal fraud block (reference ID, escalating
    lock, alert, admin page, self-unlock all work as for every other block). Returns True when a block was created.
    """
    if not extras or not extras.get('points') or risk_after.get('decision') != 'BLOCK' or risk_before.get('decision') == 'BLOCK':
        return False
    now = now if now is not None else time.time()
    why = f"High combined payment risk (score {risk_after['score']}): " + '; '.join(extras['reasons'])
    if session_id:
        _S._block_key(f'session:{session_id}', now, 'carding', why, account_id or '')
    if account_id:
        _S._block_key(f'account:{account_id}', now, 'carding', why, account_id)
    return True
