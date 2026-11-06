"""A session block belongs to the account that caused it; another account in the same tab is not punished."""
import os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import account_scout as S

def ok(m): print('ok ', m)
now = time.time(); SID = 'tab-1'; A, B = 'exporter:A', 'exporter:B'
S._block_key(f'session:{SID}', now, 'carding', 'test', A)
S._block_key(f'account:{A}', now, 'carding', 'test', A)
S._block_key('card:fp-A', now, 'carding', 'test', A)

r = S.record_card_authorization(SID, 'fp-A2', None, '1.1.1.1', account_id=A, timestamp=now + 5)
assert r['status'] == 'CARDING_RED_FLAG'; ok('the blocked account is still refused in its own tab')
r = S.record_card_authorization(SID, 'fp-B', None, '1.1.1.1', account_id=B, timestamp=now + 5)
assert r['status'] != 'CARDING_RED_FLAG', r; ok('a different account in the same tab is NOT refused by the first account\'s session block')
r = S.record_card_authorization(SID, 'fp-A', None, '1.1.1.1', account_id=B, timestamp=now + 6)
assert r['status'] == 'CARDING_RED_FLAG'; ok('...but a card that was blocked stays blocked for everyone')
r = S.record_transaction_event(SID, now + 7, account_id=B, ip='1.1.1.1')
assert not r.get('active_block'), r; ok('speed check: the other account is not frozen by the first account\'s session block either')
S._block_key('session:tab-2', now, 'bot', 'test', '')
r = S.record_transaction_event('tab-2', now + 7, account_id=B, ip='1.1.1.1')
assert r.get('status') == 'BOT_RED_FLAG'; ok('a session block with no account owner still applies to everyone')
print('\nALL SESSION-OWNER TESTS PASSED')
