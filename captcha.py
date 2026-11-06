"""
CAPTCHA step for Problem 4 (bot speed) using Cloudflare Turnstile.

Flow: the first too-fast payment is refused with "slow down" AND a Turnstile challenge. A real person solves it,
the server confirms the answer with Cloudflare, and that person's speed strikes are cleared so they carry on.
A bot that ignores or fails the challenge just makes the next too-fast payment, which is strike 2 -> block
(the existing rule, unchanged).

Off unless CAPTCHA_PROVIDER=turnstile and both keys are set, so nothing changes for anyone who does not use it.
  CAPTCHA_PROVIDER=turnstile
  TURNSTILE_SITE_KEY=...      (public, sent to the browser)
  TURNSTILE_SECRET_KEY=...    (private, stays on the server)
Cloudflare's published TEST keys (a widget that always passes) are in start.bat / start.sh for development.
"""
import json
import os
import threading
import time
import urllib.parse
import urllib.request

import account_scout as _scout

SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
_CFG = _scout.POLICY.get('captcha') or {}
_MAX_PASSES = _CFG.get('max_passes_per_hour', 2)
_TIMEOUT = _CFG.get('verify_timeout_seconds', 5)

_PASSES = {}          # account_id -> [timestamps of successful challenges in the last hour]
_STEPUP_PASS = {}      # account_id -> time until which ONE step-up payment is allowed after a human check
_CARD_PASS = {}       # account_id -> time until which ONE more card attempt is allowed after a human check
_LOCK = threading.Lock()


def is_enabled():
    return (os.environ.get('CAPTCHA_PROVIDER', '').strip().lower() == 'turnstile'
            and bool(os.environ.get('TURNSTILE_SITE_KEY', '').strip())
            and bool(os.environ.get('TURNSTILE_SECRET_KEY', '').strip()))


def site_key():
    return os.environ.get('TURNSTILE_SITE_KEY', '').strip()


def _siteverify(response_token, remote_ip=''):
    """Asks Cloudflare whether this challenge answer is genuine. Returns Cloudflare's JSON."""
    fields = {'secret': os.environ.get('TURNSTILE_SECRET_KEY', '').strip(), 'response': response_token}
    if remote_ip:
        fields['remoteip'] = remote_ip
    req = urllib.request.Request(SITEVERIFY_URL, urllib.parse.urlencode(fields).encode('utf-8'),
                                 {'Content-Type': 'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
        return json.loads(r.read().decode('utf-8'))


def complete_challenge(account_id, session_id, response_token, remote_ip='', now=None, purpose='speed'):
    """
    Verify the answer and, if genuine, clear this person's speed strikes so they can continue.
    Fails CLOSED: any error talking to Cloudflare counts as "not verified".
    """
    now = now if now is not None else time.time()
    if not is_enabled():
        return {'success': False, 'error': 'CAPTCHA is not enabled on this server.'}
    if not response_token:
        return {'success': False, 'error': 'Please complete the check first.'}
    if _scout._STORE.is_blocked(f'account:{account_id}', now):
        return {'success': False, 'error': 'This account is blocked. A check cannot lift a block.'}
    with _LOCK:
        recent = [t for t in _PASSES.get(account_id, []) if now - t < 3600]
        _PASSES[account_id] = recent
        if len(recent) >= _MAX_PASSES:
            return {'success': False, 'error': 'Too many checks for this account. Please wait before trying again.'}
    try:
        result = _siteverify(response_token, remote_ip)
    except Exception:
        return {'success': False, 'error': 'Could not reach the verification service. Please try again.'}
    if not result.get('success'):
        return {'success': False, 'error': 'The check did not pass. Please try again.'}
    with _LOCK:
        _PASSES[account_id].append(now)
    if purpose == 'stepup':
        with _LOCK:
            _STEPUP_PASS[account_id] = now + 300     # one payment is allowed to continue; speed strikes are left alone
        return {'success': True, 'message': 'Thanks, you are verified. Please press Pay again to complete your payment.'}
    if purpose == 'card':
        with _LOCK:
            _CARD_PASS[account_id] = now + 300       # one more card attempt is allowed; speed strikes are left alone
        return {'success': True, 'message': 'Thanks, you are verified. You can try your payment again.'}
    counters = [f'botstrike:{account_id}', f'rate:{account_id}']
    if session_id:
        counters += [f'botstrike:{session_id}', f'botattempt:{session_id}', f'lastseen:{session_id}',
                     f'lastip:{session_id}', f'rate:session:{session_id}', f'botstrike:session:{session_id}']
    for c in counters:
        _scout._STORE.clear(c)
    return {'success': True, 'message': 'Thanks, you are verified. You can continue your payment.'}


def card_gate(account_id, now=None):
    """
    Opt-in (CAPTCHA_ON_CARD_FAILURES=1). One failure before the card-testing block, a human check is required
    before another card can be tried. A bot cannot continue guessing cards; a real person solves it and carries on.
    """
    if not (is_enabled() and os.environ.get('CAPTCHA_ON_CARD_FAILURES', '').strip() == '1' and account_id):
        return None
    now = now if now is not None else time.time()
    if _scout._STORE.is_blocked(f'account:{account_id}', now):
        return None                                   # already blocked: the normal block message applies
    cfg = _scout.CARDING_POLICY['account_failures']
    fails = _scout._STORE.peek_sliding_count(f'failed:account:{account_id}', now, cfg['window_seconds'])
    if fails < cfg['count'] - 1:
        return None
    with _LOCK:
        until = _CARD_PASS.get(account_id)
        if until and now < until:
            _CARD_PASS.pop(account_id, None)          # a pass covers exactly one more attempt
            return None
    return {'success': False, 'captcha_required': True, 'captcha_purpose': 'card', 'captcha_site_key': site_key(),
            'error': 'Several payments have failed in a row. Please complete a quick check before trying another card.'}


def step_up_gate(account_id, now=None):
    """
    When the risk score says "ask for extra proof" (30-59), the payment is held until the person passes the human check
    (the local test provider has no 3-D Secure, so this is its stand-in). One pass lets exactly one payment continue.
    Off unless Turnstile is configured; switch off with STEPUP_CHECK=0.
    """
    if not (is_enabled() and os.environ.get('STEPUP_CHECK', '1').strip() != '0' and account_id):
        return None
    now = now if now is not None else time.time()
    with _LOCK:
        until = _STEPUP_PASS.get(account_id)
        if until and now < until:
            _STEPUP_PASS.pop(account_id, None)
            return None
    return {'success': False, 'captcha_required': True, 'captcha_purpose': 'stepup', 'captcha_site_key': site_key(),
            'error': 'For your security we need one quick extra check before this payment goes through.'}
