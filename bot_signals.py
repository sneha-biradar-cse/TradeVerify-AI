"""
Extra bot signals for Problem 4 that catch bots the raw 0.8 s speed rule misses (policy: fraud_policy.json -> hardening):

  1. Form-fill time: a person needs a moment to type card details. If a payment arrives less than `min_fill_ms`
     after the payment form was opened (or the form was never opened at all), it is a strike.
  2. Steady rhythm: a script that waits exactly N seconds between payments is "slow" but machine-regular.
     Several gaps with almost no variation is a strike. People are irregular.

Both feed the SAME strike counter as the speed rule: the first is a warning (with the human-check if enabled),
a repeat within the strike window blocks. Memory is per process, like the rest of the fraud store in memory mode.
"""
import statistics
import threading
import time
from collections import deque

import account_scout as _scout

_H = _scout.POLICY.get('hardening') or {}
_FILL = _H.get('form_fill') or {}
_RHY = _H.get('rhythm') or {}

_LOCK = threading.Lock()
_FORM_OPEN = {}      # account_id -> time the payment form was last opened
_ATTEMPTS = {}       # account_id -> deque of recent payment start times


def mark_form_open(account_id, now=None):
    if account_id:
        with _LOCK:
            _FORM_OPEN[account_id] = now if now is not None else time.time()


def reset_account(account_id):
    """Forget the rhythm history (called when a block is lifted, so a restored customer is not flagged again)."""
    if account_id:
        with _LOCK:
            _ATTEMPTS.pop(account_id, None)


def check_attempt(account_id, session_id, ip, now=None):
    """Called once per payment start. Returns None if fine, or a bot-result dict (warning, or block on a repeat)."""
    if not account_id:
        return None
    now = now if now is not None else time.time()
    reasons = []
    with _LOCK:
        if _FILL.get('enabled', True):
            opened = _FORM_OPEN.get(account_id)
            min_ms = _FILL.get('min_fill_ms', 1500)
            if opened is None:
                if _FILL.get('require_form_open', True):
                    reasons.append('the payment form was not opened first')
                    _FORM_OPEN[account_id] = now          # so an honest retry a few seconds later is measured fairly
            elif (now - opened) * 1000 < min_ms:
                reasons.append(f'card details arrived {round((now - opened) * 1000)} ms after the form opened, '
                               f'a person needs {min_ms} ms or more')
        need = int(_RHY.get('min_gaps', 4)) + 1
        q = _ATTEMPTS.get(account_id)
        if q is None or q.maxlen != need:
            q = _ATTEMPTS[account_id] = deque(q or [], maxlen=need)
        q.append(now)
        if _RHY.get('enabled', True) and len(q) == need:
            pts = list(q)
            gaps = [b - a for a, b in zip(pts, pts[1:])]
            mean = sum(gaps) / len(gaps)
            if 0 < mean <= _RHY.get('max_mean_gap_seconds', 15) and (statistics.pstdev(gaps) / mean) < _RHY.get('max_variation', 0.08):
                reasons.append(f'{len(gaps)} payments at machine-regular intervals (about {mean:.1f} s apart)')
                # history is kept on purpose: a script that carries on stays regular and is blocked on its next
                # payment, while a person who pauses breaks the pattern and is not flagged again.
    if not reasons:
        return None
    return _scout.record_slow_bot_signal(session_id, account_id, ip, '; '.join(reasons), now)
