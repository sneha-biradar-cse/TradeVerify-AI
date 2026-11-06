"""
Self-unlock for genuine customers (improvement #3) and block details for the UI (#4 reference IDs).

A customer whose account got a FIRST-time fraud lock can prove it is really them with a one-time code sent
to the account's own email (same delivery as login) and lift the lock themselves, instead of waiting for an
admin. Repeat locks and manual-review locks can NOT be self-unlocked, so an attacker cannot keep cycling.
Thresholds live in fraud_policy.json -> "escalation".
"""
import os
import secrets
import threading
import time
import hmac

import account_scout as _scout
from auth_engine import _USERS, _send_otp

_ESC = _scout.POLICY.get("escalation") or {}
_TTL = _ESC.get("unlock_otp_ttl_seconds", 300)
_MAX_ATTEMPTS = _ESC.get("unlock_otp_max_attempts", 3)
_RESEND = _ESC.get("unlock_otp_resend_seconds", 30)
_MAX_LEVEL = _ESC.get("self_unlock_max_level", 1)

_PENDING = {}          # account_id -> {'code','expires','attempts','sent_at'}
_LOCK = threading.Lock()


def _dev_mode():
    return os.environ.get('ENVIRONMENT', 'production').strip().lower() in ('development', 'dev', 'test')


def _account_block(account_id, now=None):
    """The active account-level block (with its meta), or None."""
    now = now if now is not None else time.time()
    key = f'account:{account_id}'
    for b in _scout.list_blocked(now):
        if b['key'] == key:
            return b
    return None


def block_details(account_id, now=None):
    """Everything the UI needs about the current lock: reference, level, time left, whether the customer may self-unlock."""
    b = _account_block(account_id, now)
    if not b:
        return {'blocked': False}
    m = b.get('meta') or {}
    level = int(m.get('lock_level') or 1)
    needs_review = bool(m.get('needs_review'))
    can = (not needs_review) and level <= _MAX_LEVEL
    mins = max(1, round(b['seconds_remaining'] / 60))
    if needs_review:
        msg = f"This account is locked for manual review. Please contact support and quote reference {m.get('reference', '')}."
    elif not can:
        msg = (f"This is a repeat lock (level {level}), so it clears automatically in about {mins} min. "
               f"If you need access sooner, contact support and quote reference {m.get('reference', '')}.")
    else:
        msg = f"Payments are paused for about {mins} min. If this was you, verify with a one-time code to unblock now."
    return {'blocked': True, 'reference': m.get('reference', ''), 'lock_level': level, 'needs_review': needs_review,
            'seconds_remaining': b['seconds_remaining'], 'can_self_unlock': can, 'unlock_message': msg}


def enrich_status(status, account_id):
    """Adds reference / lock level / self-unlock info to the header-badge status when the account is blocked."""
    try:
        if status.get('state') == 'blocked':
            d = block_details(account_id)
            if d.get('blocked'):
                status.update({k: d[k] for k in ('reference', 'lock_level', 'needs_review', 'seconds_remaining',
                                                 'can_self_unlock', 'unlock_message')})
                status['details'] = d['unlock_message'] + (f" Reference: {d['reference']}." if d['reference'] else '')
    except Exception:
        pass
    return status


def request_unlock(account_id, now=None):
    """Step 1: eligibility checks, then email (or dev-console) a one-time code to the account owner."""
    now = now if now is not None else time.time()
    d = block_details(account_id, now)
    if not d.get('blocked'):
        return {'success': False, 'error': 'Your account is not blocked.'}
    if not d['can_self_unlock']:
        return {'success': False, 'error': d['unlock_message'], 'reference': d['reference']}
    with _LOCK:
        cur = _PENDING.get(account_id)
        if cur and now - cur['sent_at'] < _RESEND:
            wait = int(_RESEND - (now - cur['sent_at'])) + 1
            return {'success': False, 'error': f'A code was just sent. You can request another in {wait} s.'}
        code = f"{secrets.randbelow(10 ** 6):06d}"
        _PENDING[account_id] = {'code': code, 'expires': now + _TTL, 'attempts': 0, 'sent_at': now}
    user = _USERS.get(account_id) or {}
    import otp_delivery
    res = otp_delivery.send(user, code, 'unlock')
    if not res['sent'] and not _dev_mode():
        with _LOCK:
            _PENDING.pop(account_id, None)             # fail closed in production: nothing delivered, no unlock, no code on screen
        return {'success': False, 'error': 'We could not send your one-time code. Please contact support and quote reference '
                                           + d['reference'] + '.', 'reference': d['reference']}
    where = ' and '.join(res['hints'].values()) if res['sent'] else ''
    out = {'success': True, 'reference': d['reference'], 'expires_in_seconds': _TTL,
           'delivery': res['delivery'] if res['sent'] else 'console',
           'message': ('We sent a one-time code to ' + where + '.') if res['sent'] else 'No email or SMS is set up, so a TEST code is used (development only).'}
    if not res['sent'] and _dev_mode():
        import logging
        logging.getLogger('auth_engine').warning('account_unlock [DEV, nothing delivered]: unblock code for %s is %s', account_id, code)
        from security import show_dev_hints
        if show_dev_hints():
            out['demo_otp_code'] = code        # development convenience only, same idea as the login page
    return out


def verify_unlock(account_id, code, now=None):
    """Step 2: right code -> clear this account's whole fraud incident (session, account and card keys)."""
    now = now if now is not None else time.time()
    d = block_details(account_id, now)
    if not d.get('blocked'):
        return {'success': False, 'error': 'Your account is not blocked.'}
    if not d['can_self_unlock']:
        return {'success': False, 'error': d['unlock_message'], 'reference': d['reference']}
    with _LOCK:
        cur = _PENDING.get(account_id)
        if not cur or now > cur['expires']:
            _PENDING.pop(account_id, None)
            return {'success': False, 'error': 'That code has expired. Please request a new one.'}
        cur['attempts'] += 1
        ok = hmac.compare_digest(str(code or '').strip(), cur['code'])
        if not ok:
            if cur['attempts'] >= _MAX_ATTEMPTS:
                _PENDING.pop(account_id, None)
                return {'success': False, 'error': 'Too many wrong codes. Please request a new code.'}
            left = _MAX_ATTEMPTS - cur['attempts']
            return {'success': False, 'error': f'Incorrect code. {left} attempt{"s" if left != 1 else ""} left.'}
        _PENDING.pop(account_id, None)
    cleared = False
    counters = [f'failed:account:{account_id}', f'attempts:account:{account_id}']
    for b in _scout.list_blocked(now):
        if b['key'] == f'account:{account_id}' or (b.get('meta') or {}).get('account_id') == account_id:
            key = b['key']
            if key.startswith('card:'):
                counters.append(f"card_fail:{key[len('card:'):]}")
            elif key.startswith('session:'):
                sid = key[len('session:'):]
                counters += [f'failed:session:{sid}', f'attempts:session:{sid}']
            if _scout.unblock(key):
                cleared = True
    for c in counters:    # clean slate, so one more decline does not instantly re-block the customer
        _scout._STORE.clear(c)
    return {'success': True, 'cleared': cleared, 'reference': d['reference'],
            'message': 'Your account is unblocked. You can try your payment again.'}
