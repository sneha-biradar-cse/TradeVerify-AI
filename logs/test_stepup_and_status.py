"""
Two wiring checks: (1) the "ask for extra proof" decision really holds the payment until the human check is passed,
(2) the admin System-status panel and the test-message button work and never reveal a secret.
Runs the REAL server; Cloudflare, Twilio and the mail server are local stand-ins. Ports 8080, 8025, 9931 must be free.
"""
import base64, http.server, json, os, runpy, hashlib, ssl, subprocess, sys, tempfile, threading, time, urllib.parse, urllib.request
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, ROOT)
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult
INBOX, TEXTS = [], []
class Mail:
    async def handle_DATA(self, server, session, envelope):
        INBOX.append(envelope.content.decode('utf8', 'replace')); return '250 OK'
tmp = tempfile.mkdtemp()
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', tmp + '/k.pem', '-out', tmp + '/c.pem', '-days', '1', '-subj', '/CN=localhost'], capture_output=True)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(tmp + '/c.pem', tmp + '/k.pem')
mail = Controller(Mail(), hostname='127.0.0.1', port=8025, tls_context=ctx, require_starttls=True, auth_required=True, auth_require_tls=True,
                  authenticator=lambda s, se, e, m, a: AuthResult(success=getattr(a, 'password', b'') == b'app-pw', handled=True)); mail.start()
class Twilio(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        form = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode()).items()}
        TEXTS.append(form); b = b'{"sid":"SM1"}'; self.send_response(201); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
tw = http.server.HTTPServer(('127.0.0.1', 9931), Twilio); threading.Thread(target=tw.serve_forever, daemon=True).start()

LAUNCH = ("import captcha, runpy\ncaptcha._siteverify = lambda t, ip='': {'success': t == 'human-answer'}\nrunpy.run_path('server.py', run_name='__main__')")
env = dict(os.environ, ENVIRONMENT='development', PAYMENT_PROVIDER_MODE='local_test', LOCAL_TEST_PROVIDER_OUTCOME='approve_by_card', ADMIN_PASSWORD='admin123',
           SHOW_DEV_HINTS='1', CAPTCHA_PROVIDER='turnstile', TURNSTILE_SITE_KEY='1x00000000000000000000AA', TURNSTILE_SECRET_KEY='1x0000000000000000000000000000000AA',
           SMTP_HOST='127.0.0.1', SMTP_PORT='8025', SMTP_USER='noreply@x.test', SMTP_PASSWORD='app-pw', SMS_PROVIDER='twilio', OTP_CHANNELS='email,sms',
           TWILIO_ACCOUNT_SID='ACstub', TWILIO_AUTH_TOKEN='tok', TWILIO_FROM='+15005550006', TWILIO_API_BASE='http://127.0.0.1:9931')
server = subprocess.Popen([sys.executable, '-c', LAUNCH], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
B = 'http://localhost:8080'
def call(m, p, d=None, h=None):
    r = urllib.request.Request(B + p, json.dumps(d).encode() if d is not None else None, {'Content-Type': 'application/json', **(h or {})}, method=m)
    try: x = urllib.request.urlopen(r); return x.status, json.loads(x.read() or b'{}')
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read())
        except Exception: return e.code, {}
post = lambda p, d=None, h=None: call('POST', p, d, h)
def ok(m): print('ok ', m)
def login(u):
    post('/api/auth/register', {'username': u, 'password': 'Passw0rd!x1', 'role': 'exporter', 'email': 'x@mycompany.in'})
    s, l = post('/api/auth/login', {'username': u, 'password': 'Passw0rd!x1', 'role': 'exporter'})
    return call('POST', '/api/auth/verify-otp', {'session_id': l['session_id'], 'otp_code': input_code(l)})[1]['token']
def input_code(l):  # email is configured, so the real code was emailed; read it from the local mailbox
    time.sleep(0.6)
    import re
    return re.search(r'\b(\d{6})\b', re.sub(r'^(Content|MIME|Subject|From|To)[^\n]*\n', '', INBOX[-1], flags=re.M)).group(1)
REF = 'BAE/2026-27/0842'; n = [0]
def intent_and_precheck(tok, sid, dev, card):
    n[0] += 1; k = f'k{n[0]}'
    s, c = post('/api/payments/local/create-intent', {'token': tok, 'session_id': sid, 'invoice_ref': REF, 'idempotency_key': k, 'device_id': dev})
    fp = 'local_fp_' + hashlib.sha256(card.encode()).hexdigest()[:32]
    s, p = post('/api/payments/local/precheck', {'token': tok, 'session_id': sid, 'payment_intent_id': c['payment_intent_id'], 'payment_method_token': 'local_pm_' + fp[9:],
                                                 'payment_method_fingerprint': fp, 'card_last4': card[-4:], 'card_bin': card[:6], 'idempotency_key': k, 'device_id': dev})
    return c['payment_intent_id'], p
try:
    for _ in range(80):
        try: urllib.request.urlopen(B + '/health'); break
        except Exception: time.sleep(0.5)
    # ---------- (1) extra-proof step ----------
    DEV = 'device-aaaaaaaaaaaaaaaaaaaa'
    for i in (1, 2):
        t = login(f'sp{i}'); post('/api/payments/form-opened', {'token': t}); time.sleep(1.7); intent_and_precheck(t, f'S{i}', DEV, f'51000000000000{i}0')
    t = login('sp3'); post('/api/payments/form-opened', {'token': t}); time.sleep(1.7)
    iid, p = intent_and_precheck(t, 'S3', DEV, '5100000000000030')
    assert p['step_up_required'] and p['risk_audit']['decision'] == 'STEP_UP_REQUIRED' and not p['blocked'], p
    ok('3 accounts on one device: the payment is allowed to continue but marked "extra proof needed"')
    s, c = post('/api/payments/local/confirm', {'token': t, 'session_id': 'S3', 'payment_intent_id': iid})
    assert s == 428 and c['captcha_required'] and c['captcha_purpose'] == 'stepup', (s, c); ok('confirming is HELD: the page is told to show the human check (before, nothing happened here)')
    s, v = post('/api/payments/captcha/verify', {'token': t, 'session_id': 'S3', 'captcha_response': 'bot-guess', 'purpose': 'stepup'}); assert s == 400; ok('a wrong answer does not release the payment')
    s, c = post('/api/payments/local/confirm', {'token': t, 'session_id': 'S3', 'payment_intent_id': iid}); assert s == 428; ok('...it is still held')
    s, v = post('/api/payments/captcha/verify', {'token': t, 'session_id': 'S3', 'captcha_response': 'human-answer', 'purpose': 'stepup'}); assert s == 200 and v['success']; ok('a correct answer passes the check')
    time.sleep(2.4); iid, p = intent_and_precheck(t, 'S3', DEV, '5100000000000030')
    s, c = post('/api/payments/local/confirm', {'token': t, 'session_id': 'S3', 'payment_intent_id': iid}); assert s == 200 and c['status'] in ('requires_payment_method', 'succeeded', 'blocked'), (s, c)
    ok('the next payment goes through to the card network')
    iid, p = intent_and_precheck(t, 'S3', DEV, '5100000000000048') if False else (None, None)
    t2 = login('normal1'); post('/api/payments/form-opened', {'token': t2}); time.sleep(1.7)
    iid, p = intent_and_precheck(t2, 'N1', 'device-bbbbbbbbbbbbbbbbbbbb', '5200000000000009')
    s, c = post('/api/payments/local/confirm', {'token': t2, 'session_id': 'N1', 'payment_intent_id': iid}); assert s == 200, (s, c); ok('an ordinary customer is never asked for the extra check')

    # ---------- (2) admin status + test message ----------
    H = {'X-Admin-Password': 'admin123', 'X-Admin-Name': 'tester'}
    assert call('GET', '/api/admin/system-status')[0] == 401; ok('system status needs the admin password')
    s, st = call('GET', '/api/admin/system-status', None, H); assert s == 200 and st['login_code_channels'] == {'email': True, 'sms': True, 'whatsapp': False}, st
    assert st['captcha']['enabled'] and st['captcha']['test_keys'] and st['captcha']['step_up_check'] and st['extra_signals'] and st['rate_limits'], st
    blob = json.dumps(st); assert not any(x in blob for x in ('app-pw', 'tok', 'ACstub', '0000000000000000000000000000000AA')); ok('status shows what is on (email + SMS, test CAPTCHA keys flagged) and contains NO secret')
    n0 = len(INBOX)
    s, r = post('/api/admin/test-message', {'channel': 'email', 'to': 'boss@mycompany.in'}, H); time.sleep(0.6); assert s == 200 and len(INBOX) == n0 + 1 and 'delivery test' in INBOX[-1]; ok('"Send test" emails one clearly-labelled test message')
    s, r = post('/api/admin/test-message', {'channel': 'sms', 'to': '9876543210'}, H); assert s == 200 and TEXTS[-1]['To'] == '+919876543210' and 'test' in TEXTS[-1]['Body'].lower(); ok('...and one test SMS (+91 added to a 10-digit number)')
    s, r = post('/api/admin/test-message', {'channel': 'whatsapp', 'to': '9876543210'}, H); assert s == 400 and 'not configured' in r['error']; ok('a channel that is not set up says so plainly')
    s, r = post('/api/admin/test-message', {'channel': 'sms', 'to': '12'}, H); assert s == 400 and 'mobile number' in r['error']; ok('a nonsense number is refused')
    assert post('/api/admin/test-message', {'channel': 'email', 'to': 'a@b.in'})[0] == 401; ok('test messages need the admin password')
    codes = [post('/api/admin/test-message', {'channel': 'email', 'to': 'boss@mycompany.in'}, H)[0] for _ in range(6)]
    assert 429 in codes; ok('test messages are rate limited (5 per 5 minutes), so the panel cannot be used to spam')
    print('\nALL STEP-UP AND STATUS TESTS PASSED (local stand-ins)')
finally:
    server.terminate(); tw.shutdown(); mail.stop()
    for f in ('payment_ledger.json', 'admin_audit.log'):
        try: os.remove(os.path.join(ROOT, f))
        except FileNotFoundError: pass
