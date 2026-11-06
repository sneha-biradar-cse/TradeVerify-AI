"""Tests for v30: form-fill time, steady rhythm, card-failure human check, admin stats."""
import os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import account_scout as S
import bot_signals as B
import captcha as C

def ok(m): print('ok ', m)
A, SID, IP = 'exporter:sig_user', 'sig-sess', '10.0.0.1'
t0 = time.time()

# --- form-fill time ---
assert B.check_attempt(A, SID, IP, t0) is not None, 'no form opened'
ok('payment without ever opening the form is flagged (warning first)')
B.reset_account(A); S._STORE.clear(f'botstrike:{A}'); B._FORM_OPEN.clear()
B.mark_form_open(A, t0 + 10)
r = B.check_attempt(A, SID, IP, t0 + 10.3)
assert r and r.get('slow_down') and '300 ms' in r['alert'], r
ok('card details 0.3 s after the form opened: warning (strike 1)')
r = B.check_attempt(A, SID, IP, t0 + 10.5)
assert r and r.get('status') == 'BOT_RED_FLAG', r
ok('the same again within the strike window: account blocked')
for k in (f'session:{SID}', f'account:{A}'): S.unblock(k)
S._STORE.clear(f'botstrike:{A}')

# --- a normal person is never flagged ---
B._FORM_OPEN.clear(); B._ATTEMPTS.clear()
B.mark_form_open(A, t0 + 100)
assert B.check_attempt(A, SID, IP, t0 + 108) is None; ok('a person who takes 8 s to fill the form is fine')
# irregular retries (declined cards): 5, 11, 14, 25 s apart
now = t0 + 108
for gap in (11, 5, 17, 9):
    now += gap
    assert B.check_attempt(A, SID, IP, now) is None
ok('irregular retries are not flagged as a steady rhythm')

# --- steady rhythm ---
B._ATTEMPTS.clear(); S._STORE.clear(f'botstrike:{A}')
B.mark_form_open(A, t0 + 200)
results = [B.check_attempt(A, SID, IP, t0 + 210 + i * 2.0) for i in range(6)]
assert all(r is None for r in results[:4]), results
assert results[4] and results[4].get('slow_down') and 'machine-regular' in results[4]['alert'], results[4]
ok('a script paying exactly every 2 s is warned on its 5th payment (a bot the 0.8 s rule would miss)')
assert results[5] and results[5].get('status') == 'BOT_RED_FLAG', results[5]
ok('...and blocked on its next payment, because it stays machine-regular')

# --- unblock forgets the rhythm so a restored customer is not re-flagged at once ---
S._block_key(f'account:{A}', t0 + 300, 'bot', 'test', A)
B._ATTEMPTS[A] = B.deque([1, 2, 3, 4, 5], maxlen=5)
S.unblock(f'account:{A}')
assert A not in B._ATTEMPTS; ok('unblocking clears the rhythm history')

# --- card-failure human check (opt-in) ---
for k in ('CAPTCHA_PROVIDER', 'TURNSTILE_SITE_KEY', 'TURNSTILE_SECRET_KEY', 'CAPTCHA_ON_CARD_FAILURES'): os.environ.pop(k, None)
C2 = 'exporter:gate_user'
now = time.time()
for i in range(3): S._STORE.sliding_count(f'failed:{C2}'.replace(f'failed:{C2}', f'failed:account:{C2}'), now, 600)
assert C.card_gate(C2, now) is None; ok('card gate is off by default')
os.environ.update(CAPTCHA_PROVIDER='turnstile', TURNSTILE_SITE_KEY='s', TURNSTILE_SECRET_KEY='k', CAPTCHA_ON_CARD_FAILURES='1')
g = C.card_gate(C2, now); assert g and g['captcha_required'] and g['captcha_purpose'] == 'card'; ok('after 3 failed payments the next card needs a human check')
assert C.card_gate('exporter:fresh', now) is None; ok('an account with fewer failures is not asked')
C._siteverify = lambda tok, ip='': {'success': True}
assert C.complete_challenge(C2, 'x', 'ans', now=now, purpose='card')['success']
assert C.card_gate(C2, now + 1) is None; ok('a passed check allows exactly one more card attempt')
assert C.card_gate(C2, now + 2) is not None; ok('...and then the check is needed again')
S._block_key(f'account:{C2}', now, 'carding', 'test', C2)
assert C.card_gate(C2, now + 3) is None; ok('an already-blocked account gets the normal block message, not a check')

# --- stats ---
st = S.incident_stats()
assert st['total'] >= 3 and st['bot'] >= 1 and st['carding'] >= 1; ok('incident stats count bot and card-testing blocks')
print('\nALL BOT-SIGNAL / HUMAN-CHECK TESTS PASSED')
