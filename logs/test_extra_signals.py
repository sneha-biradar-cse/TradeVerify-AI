"""Tests for the three extra protections: device id, card family (first 6 digits), security-code / postcode result."""
import os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import account_scout as S
import extra_signals as X

def ok(m): print('ok ', m)
now = time.time()
D1, D2 = 'dev-aaaaaaaaaaaaaaaaaaaa', 'dev-bbbbbbbbbbbbbbbbbbbb'

# ---------- input cleaning ----------
assert X.clean_device_id('abc') == '' and X.clean_device_id('x' * 70) == '' and X.clean_device_id('<script>alert(1)</script>') == '' and X.clean_device_id(D1) == D1
ok('a device id must be a well-formed random id; junk is treated as "no device id"')
assert X.clean_bin('4111 1111 1111 1111') == '411111' and X.clean_bin('4111') == '' and X.clean_bin(None) == ''
ok('card family digits: first 6 only, and nothing when fewer than 6 are known')
assert [X.norm_check(v) for v in ('pass', 'FAIL', None, '', 'weird')] == ['pass', 'fail', 'unchecked', 'unchecked', 'unavailable']
ok('card network answers are reduced to pass / fail / unavailable / unchecked')

# ---------- 1. device id ----------
r = X.evaluate_attempt('exporter:a', D1, 'fp1', now=now)
assert r['points'] == 0; ok('one card on one device adds nothing')
for i in range(2, 5): r = X.evaluate_attempt('exporter:a', D1, f'fp{i}', now=now + i)
assert r['points'] == 0 and r['signals']['device_cards'] == 4
r = X.evaluate_attempt('exporter:a', D1, 'fp5', now=now + 6)
assert r['points'] == 35 and 'different cards' in r['reasons'][0]; ok('5 different cards from one device adds 35 points')
r = X.evaluate_attempt('exporter:a', D1, 'fp5', now=now + 7)
assert r['signals']['device_cards'] == 5; ok('the same card again is not counted as a new card')
r = X.evaluate_attempt('exporter:a', D1, 'fp1', now=now + 700)
assert r['points'] == 0; ok('old attempts fall out of the 10-minute window')
X.evaluate_attempt('exporter:b1', D2, 'g1', now=now); X.evaluate_attempt('exporter:b2', D2, 'g1', now=now + 1)
r = X.evaluate_attempt('exporter:b3', D2, 'g1', now=now + 2)
assert r['points'] == 40 and 'accounts' in r['reasons'][0]; ok('3 different accounts on one device adds 40 points')
r = X.evaluate_attempt('exporter:z', '', 'g9', now=now)
assert r['points'] == 0 and 'device_cards' not in r['signals']; ok('no device id = no device signal (never a penalty)')

# ---------- 2. card family ----------
for i in range(3): r = X.evaluate_attempt('exporter:c', '', f'c{i}', bin6='411111', now=now + i)
assert r['points'] == 0
r = X.evaluate_attempt('exporter:c', '', 'c3', bin6='411111', now=now + 4)
assert r['points'] == 30 and 'card family' in r['reasons'][0]; ok('4 different cards sharing the first 6 digits adds 30 points')
for i in range(4): r = X.evaluate_attempt('exporter:d', '', f'd{i}', bin6=f'41111{i}', now=now + i)
assert r['points'] == 0; ok('4 cards from DIFFERENT families add nothing')
for i in range(5): r = X.evaluate_attempt('exporter:e', '', f'e{i}', brand='visa', country='IN', funding='debit', now=now + i)
assert r['points'] == 0
r = X.evaluate_attempt('exporter:e', '', 'e5', brand='visa', country='IN', funding='debit', now=now + 6)
assert r['points'] == 15 and 'weaker' in r['reasons'][0]; ok('without the digits, brand+country+type is a weaker stand-in (needs 6 cards, adds only 15)')

# ---------- 3. security code / postcode ----------
assert X.evaluate_checks('pass', 'pass')['points'] == 0
assert X.evaluate_checks('fail', 'pass')['points'] == 25 and X.evaluate_checks('pass', 'fail')['points'] == 25 and X.evaluate_checks('fail', 'fail')['points'] == 50
ok('security code "no match" = 25, postcode "no match" = 25, both = 50')
assert X.evaluate_checks('unavailable', 'unchecked')['points'] == 0 and X.evaluate_checks(None, None)['points'] == 0
ok('"unavailable" / "not checked" add NOTHING (many countries never answer)')
class PM:  # shaped like a Stripe PaymentMethod
    class card:
        brand, country, funding, iin = 'visa', 'IN', 'credit', None
        checks = {'cvc_check': 'fail', 'address_postal_code_check': 'pass'}
assert X.checks_from_stripe_pm(PM) == ('fail', 'pass'); assert X.card_info_from_stripe_pm(PM) == {'brand': 'visa', 'country': 'IN', 'funding': 'credit', 'bin6': ''}
class PM2: card = None
assert X.checks_from_stripe_pm(PM2) == (None, None); ok('Stripe results are read safely, and missing data never crashes')

# ---------- combined with the existing risk score ----------
base = {'score': 10, 'decision': 'ALLOW', 'reasons': ['payment authorization failed'], 'details': ''}
a = X.apply_to_risk(base, X.evaluate_checks('fail', 'pass'))
assert a['score'] == 35 and a['decision'] == 'STEP_UP_REQUIRED'; ok('a failed payment (10) + code mismatch (25) = 35: asks for extra proof, is NOT blocked')
a = X.apply_to_risk(base, X.evaluate_checks('fail', 'fail'))
assert a['score'] == 60 and a['decision'] == 'REVIEW'; ok('+ postcode mismatch too = 60: REVIEW')
big = {'score': 45, 'decision': 'STEP_UP_REQUIRED', 'reasons': [], 'details': ''}
e = X.merge(X.evaluate_checks('fail', 'fail'))
a = X.apply_to_risk(big, e); assert a['decision'] == 'BLOCK'
S._BLOCK_HISTORY.clear()
assert X.block_if_needed(big, a, e, 'exporter:blk', 'sess-blk', now)
m = S._STORE.get_block_meta('account:exporter:blk')
assert m['reference'].startswith('TV-') and m['lock_level'] == 1 and 'High combined payment risk' in m['reason']
ok('when the extra points push the score to BLOCK it becomes a normal block: reference ID, lock level, reason')
assert not X.block_if_needed(big, big, X.merge(), 'exporter:q', 's', now); ok('no extra points = no new block (existing behaviour untouched)')
assert not X.block_if_needed({'decision': 'BLOCK'}, {'decision': 'BLOCK'}, e, 'exporter:q', 's', now); ok('a score that was ALREADY a block is left to the existing code')
print('\nALL EXTRA-SIGNAL TESTS PASSED')
