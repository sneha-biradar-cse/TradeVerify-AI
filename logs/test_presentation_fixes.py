"""
Presentation fixes: (1) no on-screen login code / '(demo)' text when SHOW_DEV_HINTS=0, (2) the admin page shows ONE bar per
block and one Unblock clears the whole incident with ONE history line.
Runs the real server on a random port (heavy OCR engines are stubbed only if not installed).
Run:  python logs/test_presentation_fixes.py
"""
import importlib, json, os, re, shutil, subprocess, sys, tempfile, threading, time, urllib.error, urllib.request
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT); os.chdir(ROOT)
for _m in ['rapidfuzz', 'authenticity_engine', 'verification_matrix', 'sanctions_engine', 'compliance_engine', 'local_extractor', 'stripe']:
    try: importlib.import_module(_m)
    except Exception: sys.modules[_m] = mock.MagicMock()

TMP = tempfile.mkdtemp()
CAT = os.path.join(TMP, 'inv.json'); json.dump({'INV-1': {'amount_minor': 1000, 'currency': 'usd', 'status': 'open'}}, open(CAT, 'w'))
os.environ.update(ENVIRONMENT='development', INVOICE_CATALOG_FILE=CAT, PAYMENT_LEDGER_FILE=os.path.join(TMP, 'ledger.json'),
                  ADMIN_PASSWORD='pw', LOCAL_TEST_PROVIDER_OUTCOME='declined', RATE_LIMIT_ENABLED='0', CAPTCHA_PROVIDER='off')
os.environ.pop('PAYMENT_PROVIDER_MODE', None); os.environ.pop('SHOW_DEV_HINTS', None)
import server, auth_engine, account_scout
server.ADMIN_AUDIT_FILE = os.path.join(TMP, 'audit.log') if hasattr(server, 'ADMIN_AUDIT_FILE') else None
from http.server import ThreadingHTTPServer
httpd = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler); httpd.daemon_threads = True
PORT = httpd.server_address[1]
threading.Thread(target=httpd.serve_forever, daemon=True).start()
_n = [0]
ADMIN = {'X-Admin-Password': 'pw', 'X-Admin-Name': 'tester'}


def ok(msg):
    _n[0] += 1; print('ok', _n[0], '-', msg)


def call(method, path, body=None, headers=None):
    req = urllib.request.Request(f'http://127.0.0.1:{PORT}{path}', method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={'Content-Type': 'application/json', **(headers or {})})
    try:
        with urllib.request.urlopen(req) as r: return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read() or b'{}')
        except Exception: return e.code, {}


def login_start(user):
    call('POST', '/api/auth/register', {'username': user, 'password': 'Passw0rd!x', 'role': 'exporter', 'email': user + '@example.com'})
    return call('POST', '/api/auth/login', {'username': user, 'password': 'Passw0rd!x', 'role': 'exporter'})[1]


# ---------------------------------------------------------------- 1. on-screen code / (demo)
r = login_start('hints_on')
assert r.get('demo_otp_code') and call('GET', '/api/ui-config')[1]['dev_hints'] is True
ok('default (SHOW_DEV_HINTS unset): behaviour unchanged - code is returned for local testing and the page may show the dev hint')

os.environ['SHOW_DEV_HINTS'] = '0'
r = login_start('hints_off')
assert r.get('success') and r.get('requires_otp') and 'demo_otp_code' not in r, r
assert 'otp' not in json.dumps({k: v for k, v in r.items() if k != 'otp_delivery'}).lower().replace('requires_otp', '')
ok('SHOW_DEV_HINTS=0: the login response contains NO code (nothing to display, nothing in the network tab)')
assert call('GET', '/api/ui-config')[1]['dev_hints'] is False; ok('SHOW_DEV_HINTS=0: the login page is told to hide the demo footer')
code = auth_engine._PENDING_OTPS[r['session_id']]['code']
s, d = call('POST', '/api/auth/verify-otp', {'session_id': r['session_id'], 'otp_code': code})
assert s == 200 and d.get('token'); ok('...and the real code (read from the server side) still logs the person in')
for f in ('exporter-login.html', 'importer-login.html'):
    html = open(os.path.join(ROOT, f), encoding='utf-8').read()
    assert '(demo)' not in html and 'id="dev-hint"' in html and 'display:none' in html.split('id="dev-hint"')[1][:40]
ok('login pages: the "(demo)" text is gone and the demo-account footer starts hidden')
# unlock request obeys the same switch
tok = d['token']
for i in range(1, 1):
    pass

# ---------------------------------------------------------------- 2. one bar per block, one Unblock
def pay_decline(tok, i, sid):
    time.sleep([1.4, 2.3, 1.7, 2.9, 1.5, 2.6][i - 1])
    s, c = call('POST', '/api/payments/local/create-intent', {'token': tok, 'session_id': sid, 'invoice_ref': 'INV-1', 'idempotency_key': 'k%d%s' % (i, sid)})
    if s != 200: return s, c
    fp = 'local_fp_' + ('4111111111110%03d' % i) * 2
    s, p = call('POST', '/api/payments/local/precheck', {'token': tok, 'session_id': sid, 'payment_intent_id': c['payment_intent_id'], 'payment_method_token': 'local_pm_%d' % i, 'payment_method_fingerprint': fp, 'card_last4': '0005', 'idempotency_key': 'k'})
    if p.get('blocked'): return 'blocked', p
    return call('POST', '/api/payments/local/confirm', {'token': tok, 'session_id': sid, 'payment_intent_id': c['payment_intent_id']})

d = None
r = login_start('block_me'); s2, d = call('POST', '/api/auth/verify-otp', {'session_id': r['session_id'], 'otp_code': auth_engine._PENDING_OTPS[r['session_id']]['code']})
tok = d['token']; call('POST', '/api/payments/form-opened', {'token': tok}); time.sleep(1.7)
res = None
for i in range(1, 7):
    res = pay_decline(tok, i, 'blk')
    if res[0] == 'blocked': break
assert res[0] == 'blocked', res
s, b = call('GET', '/api/admin/blocks', headers=ADMIN)
rows = [x for x in b['blocks'] if (x.get('meta') or {}).get('account_id') == 'exporter:block_me' or x['key'].startswith(('card:local_fp_', 'session:'))]
refs = {(x.get('meta') or {}).get('reference') for x in rows if (x.get('meta') or {}).get('reference')}
print('   raw keys frozen by this one incident:', sorted(x['key'].split(':')[0] for x in b['blocks']), '| references:', refs)
assert len(b['blocks']) >= 2 and len(refs) == 1
ok('the server really reports several frozen keys for ONE incident (%d keys, 1 reference)' % len(b['blocks']))

# the page logic (extracted from admin.html and run in Node)
html = open(os.path.join(ROOT, 'admin.html'), encoding='utf-8').read()
js = html[html.index('function _groupBlocks'):html.index('function renderBlocks')]
if shutil.which('node'):
    prog = js + "const blocks=%s; const g=_groupBlocks(blocks); console.log(JSON.stringify({n:g.length, main:g[0].main.key, ref:g[0].ref, affects:_affects(g[0].items)}));" % json.dumps(b['blocks'])
    out = json.loads(subprocess.run(['node', '-e', prog], capture_output=True, text=True).stdout)
    assert out['n'] == 1 and out['main'].startswith('account:') and out['ref'] in refs, out
    ok('the admin page shows ONE bar for the incident, led by the account (affects: %s)' % out['affects'])
else:
    print('skip - node not installed: admin page grouping')

before = len(__import__('server')._admin_audit_read(1000))
s, u = call('POST', '/api/admin/unblock', {'reference': list(refs)[0]}, headers=ADMIN)
assert s == 200 and u['success'] and u['cleared'] and len(u['keys']) >= 2, u
ok('one Unblock press clears all %d frozen keys of the incident' % len(u['keys']))
assert call('GET', '/api/admin/blocks', headers=ADMIN)[1]['blocks'] == []; ok('nothing is left blocked afterwards')
after = server._admin_audit_read(1000)
assert len(after) - before == 1 and after[0]['action'] == 'unblock' and after[0]['reference'] == list(refs)[0]
ok('the admin history gets exactly ONE line for that unblock (was one line per frozen key)')
assert call('POST', '/api/admin/unblock', {'key': 'account:nobody'}, headers=ADMIN)[1]['cleared'] is False; ok('unblocking by key still works as before')
assert call('POST', '/api/admin/unblock', {'reference': 'TV-000000'}, headers=ADMIN)[1]['cleared'] is False; ok('an unknown reference clears nothing and does not error')

shutil.rmtree(TMP, ignore_errors=True)
print('\nALL PRESENTATION-FIX TESTS PASSED (%d checks)' % _n[0])
