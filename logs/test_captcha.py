"""Tests for the Turnstile human-check step (Cloudflare is replaced by a stub, so no internet is needed)."""
import os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import account_scout as S
import captcha as C

def ok(m): print('ok ', m)
ACCT, SID = 'exporter:cap_user', 'sess-cap'
for k in ('CAPTCHA_PROVIDER', 'TURNSTILE_SITE_KEY', 'TURNSTILE_SECRET_KEY'): os.environ.pop(k, None)
assert not C.is_enabled() and not C.complete_challenge(ACCT, SID, 'x')['success']; ok('off unless provider and both keys are set')
os.environ.update(CAPTCHA_PROVIDER='turnstile', TURNSTILE_SITE_KEY='site', TURNSTILE_SECRET_KEY='secret')
assert C.is_enabled(); ok('on when configured')
assert not C.complete_challenge(ACCT, SID, '')['success']; ok('empty answer is refused')

seen = {}
def good(tok, ip=''): seen['tok'] = tok; return {'success': True}
def bad(tok, ip=''): return {'success': False, 'error-codes': ['invalid-input-response']}
def down(tok, ip=''): raise OSError('no internet')
now = time.time()
for key in (f'botstrike:{ACCT}', f'botstrike:{SID}', f'lastseen:{SID}', f'rate:{ACCT}'):
    S._STORE.sliding_count(key, now, 60)

C._siteverify = bad
assert not C.complete_challenge(ACCT, SID, 'wrong', now=now)['success']; ok('a wrong answer is refused')
C._siteverify = down
r = C.complete_challenge(ACCT, SID, 'abc', now=now); assert not r['success'] and 'Could not reach' in r['error']; ok('fails CLOSED when Cloudflare cannot be reached')
assert S._STORE.peek_sliding_count(f'botstrike:{ACCT}', now, 60) >= 1; ok('a failed check leaves the strikes in place')

C._siteverify = good
r = C.complete_challenge(ACCT, SID, 'real-answer', now=now); assert r['success'] and seen['tok'] == 'real-answer'; ok('a genuine answer passes')
assert S._STORE.peek_sliding_count(f'botstrike:{ACCT}', now, 60) == 0 and S._STORE.peek_sliding_count(f'rate:{ACCT}', now, 60) == 0
ok('a pass clears the speed strikes, so the person carries on')

r2 = C.complete_challenge(ACCT, SID, 'again', now=now + 5); assert r2['success']
r3 = C.complete_challenge(ACCT, SID, 'again2', now=now + 10); assert not r3['success'] and 'Too many' in r3['error']
ok('limited to 2 passes per hour, so a bot cannot solve its way out forever')
assert C.complete_challenge(ACCT, SID, 'later', now=now + 3700)['success']; ok('allowance returns after an hour')

S._block_key(f'account:{ACCT}', now + 4000, 'bot', 'test', ACCT)
r4 = C.complete_challenge(ACCT, SID, 'x', now=now + 4001); assert not r4['success'] and 'blocked' in r4['error']
ok('a check can never lift an existing block')
print('\nALL CAPTCHA TESTS PASSED')
