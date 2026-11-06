"""Regression tests for v28: block reference IDs, escalating locks, and OTP self-unlock (items 3 and 4)."""
import os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
os.environ.setdefault('ENVIRONMENT', 'development')
import account_scout as S
import account_unlock as U
from auth_engine import _USERS

def ok(msg): print('ok ', msg)
ACCT = 'exporter:unit_user'
_USERS[ACCT] = {'username': 'unit_user', 'role': 'exporter', 'email': ''}

def block_incident(now):
    # one detection blocks several keys in the same moment: they must share one reference + level
    S._block_key('session:s1', now, 'carding', 'test', ACCT)
    S._block_key('card:fp1', now, 'carding', 'test', ACCT)
    S._block_key(f'account:{ACCT}', now, 'carding', 'test', ACCT)

S.reset_live_state() if hasattr(S, 'reset_live_state') else None
S._BLOCK_HISTORY.clear(); U._PENDING.clear()
t0 = time.time()

# --- incident 1: level 1, normal 15-minute lock, one shared reference ---
block_incident(t0)
metas = [S._STORE.get_block_meta(k) for k in ('session:s1', 'card:fp1', f'account:{ACCT}')]
assert len({m['reference'] for m in metas}) == 1 and metas[0]['reference'].startswith('TV-'), metas
assert all(m['lock_level'] == 1 and m['lock_seconds'] == S.BLOCK_DURATION_SEC and not m['needs_review'] for m in metas)
ok('incident 1: one shared TV- reference, level 1, normal lock length')
d = U.block_details(ACCT, t0 + 1)
assert d['blocked'] and d['can_self_unlock'] and d['reference'] == metas[0]['reference']
ok('level 1 lock can be self-unlocked')

# --- OTP rules ---
r = U.request_unlock(ACCT, t0 + 1); assert r['success'] and r.get('demo_otp_code'), r
code = r['demo_otp_code']
assert not U.request_unlock(ACCT, t0 + 2)['success']; ok('resend inside the cooldown is refused')
bad = U.verify_unlock(ACCT, '000000', t0 + 3); assert not bad['success'] and '2 attempts' in bad['error'], bad
ok('wrong code is refused and attempts are counted')
good = U.verify_unlock(ACCT, code, t0 + 4); assert good['success'] and good['cleared'], good
assert not U.block_details(ACCT, t0 + 5)['blocked'] and not S._STORE.is_blocked('session:s1', t0 + 5) and not S._STORE.is_blocked('card:fp1', t0 + 5)
ok('right code clears the whole incident (account, session and card keys)')

# --- expiry and attempts lockout ---
t1 = t0 + 100
block_incident(t1)   # repeat within 24 h -> level 2
m = S._STORE.get_block_meta(f'account:{ACCT}')
assert m['lock_level'] == 2 and m['lock_seconds'] == 3600 and m['reference'] != metas[0]['reference'], m
ok('repeat lock within 24 h: level 2, 60 minutes, new reference')
assert not U.block_details(ACCT, t1 + 1)['can_self_unlock'] and not U.request_unlock(ACCT, t1 + 1)['success']
ok('level 2 cannot be self-unlocked (stops attackers cycling)')

# --- level 3 = manual review ---
S.unblock(f'account:{ACCT}')
for k in ('session:s1', 'card:fp1'): S.unblock(k)
t2 = t0 + 200
block_incident(t2)
m = S._STORE.get_block_meta(f'account:{ACCT}')
assert m['lock_level'] == 3 and m['needs_review'] and m['lock_seconds'] == 86400, m
assert 'manual review' in U.block_details(ACCT, t2 + 1)['unlock_message']
ok('level 3: 24 h lock flagged for manual review, admin only')

# --- a different account is unaffected; history ages out ---
S._block_key('account:exporter:other', t2, 'bot', 'test', 'exporter:other')
assert S._STORE.get_block_meta('account:exporter:other')['lock_level'] == 1
ok('another account starts at level 1')
S._BLOCK_HISTORY[ACCT]['times'] = [t2 - 90000]
S.unblock(f'account:{ACCT}'); 
for k in ('session:s1', 'card:fp1'): S.unblock(k)
block_incident(t2 + 90001)
assert S._STORE.get_block_meta(f'account:{ACCT}')['lock_level'] == 1
ok('old incidents age out after the 24 h history window')

# --- status enrichment for the header badge ---
st = U.enrich_status({'state': 'blocked', 'details': 'x'}, ACCT)
assert 'reference' in st and 'Reference: TV-' in st['details']
ok('security-status carries the reference ID')
print('\nALL ESCALATION / SELF-UNLOCK TESTS PASSED')
