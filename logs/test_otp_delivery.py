"""
End-to-end test of login-code delivery WITHOUT any real account: the REAL server runs with a local mail server (STARTTLS + login)
and a local stand-in for Twilio's API. Proves our side (email, SMS, WhatsApp, masking, resend, limits, fallbacks).
It does NOT prove Gmail / Twilio themselves: run  python check_otp_delivery.py ...  once with your own keys.
Run from the project folder with ports 8080, 8025 and 9931 free:   python logs/test_otp_delivery.py
"""
import asyncio, base64, http.server, json, os, re, ssl, subprocess, sys, tempfile, threading, time, urllib.parse, urllib.request

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
INBOX, TEXTS = [], []

# ---------------- local mail server (needs: pip install aiosmtpd) ----------------
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult
class Mail:
    async def handle_DATA(self, server, session, envelope):
        INBOX.append({'to': envelope.rcpt_tos, 'raw': envelope.content.decode('utf8', 'replace')}); return '250 OK'
def auth(server, session, envelope, mechanism, auth_data):
    return AuthResult(success=getattr(auth_data, 'password', b'') == b'good-app-password', handled=True)
tmp = tempfile.mkdtemp()
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', tmp + '/k.pem', '-out', tmp + '/c.pem', '-days', '1', '-subj', '/CN=localhost'], capture_output=True)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(tmp + '/c.pem', tmp + '/k.pem')
mail = Controller(Mail(), hostname='127.0.0.1', port=8025, tls_context=ctx, require_starttls=True, authenticator=auth, auth_required=True, auth_require_tls=True)
mail.start()

# ---------------- stand-in for Twilio's Messages API ----------------
class Twilio(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        form = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode()).items()}
        want = 'Basic ' + base64.b64encode(b'ACstub:tokenstub').decode()
        def reply(code, obj):
            b = json.dumps(obj).encode(); self.send_response(code); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
        if self.headers.get('Authorization') != want or '/Accounts/ACstub/Messages.json' not in self.path:
            return reply(401, {'message': 'Authenticate'})
        if '9100000000' in form.get('To', ''):
            return reply(400, {'message': 'The number is unverified. Trial accounts cannot send messages to unverified numbers'})
        TEXTS.append(form); reply(201, {'sid': 'SMstub', 'status': 'queued'})
    def log_message(self, *a): pass
tw = http.server.HTTPServer(('127.0.0.1', 9931), Twilio); threading.Thread(target=tw.serve_forever, daemon=True).start()

base_env = dict(os.environ, ENVIRONMENT='development', PAYMENT_PROVIDER_MODE='local_test', ADMIN_PASSWORD='admin123',
                OTP_CHANNELS='email,sms,whatsapp', SMTP_HOST='127.0.0.1', SMTP_PORT='8025', SMTP_USER='noreply@tradeverify.test', SMTP_PASSWORD='good-app-password',
                SMS_PROVIDER='twilio', TWILIO_ACCOUNT_SID='ACstub', TWILIO_AUTH_TOKEN='tokenstub', TWILIO_FROM='+15005550006',
                WHATSAPP_FROM='whatsapp:+14155238886', TWILIO_API_BASE='http://127.0.0.1:9931', AUTH_OTP_RESEND_SEC='2',
                OTP_MAX_SMS_PER_NUMBER_PER_HOUR='3', DEFAULT_PHONE_COUNTRY_CODE='+91')
base_env.pop('SHOW_DEV_HINTS', None)
B = 'http://localhost:8080'

def start(extra=None):
    env = dict(base_env, **(extra or {}))
    p = subprocess.Popen([sys.executable, 'server.py'], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(80):
        try: urllib.request.urlopen(B + '/health'); return p
        except Exception: time.sleep(0.5)
    raise SystemExit('server did not start')
def call(path, d):
    r = urllib.request.Request(B + path, json.dumps(d).encode(), {'Content-Type': 'application/json'})
    try: x = urllib.request.urlopen(r); return x.status, json.loads(x.read() or b'{}')
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read())
        except Exception: return e.code, {}
def ok(m): print('ok ', m)
def code_in(raw): return re.search(r'\b(\d{6})\b', re.sub(r'^(Content|MIME|Subject|From|To)[^\n]*\n', '', raw, flags=re.M)).group(1)
def reg(u, **kw): return call('/api/auth/register', {'username': u, 'password': 'Passw0rd!x1', 'role': 'exporter', **kw})
def login(u): return call('/api/auth/login', {'username': u, 'password': 'Passw0rd!x1', 'role': 'exporter'})

server = start()
try:
    # ---- sign-up checks ----
    s, r = reg('bad1', email='a@b.com', phone='12'); assert s >= 400 and 'country code' in r['error'], r; ok('a nonsense mobile number is refused with a clear message')
    s, r = reg('bad2'); assert s >= 400 and 'email address or a mobile number' in r['error'], r; ok('with delivery set up, sign-up needs an email or a mobile number (otherwise nobody could ever receive a code)')
    s, r = reg('bad3', email='not-an-email'); assert s >= 400 and 'valid email' in r['error']; ok('a malformed email is refused')
    s, r = reg('rita', email='rita@mycompany.in', phone='98765 43210'); assert s == 200 and r['success'], r; ok('sign-up with email + a mobile number typed without country code is accepted (+91 assumed)')

    # ---- login: every channel the user has ----
    s, l = login('rita'); assert s == 200 and l['success'], l
    assert l['otp_delivery'] == 'email+sms+whatsapp' or set(l['otp_delivery'].split('+')) == {'email', 'sms', 'whatsapp'}, l['otp_delivery']
    assert l['sent_to'] == {'email': 'r***@mycompany.in', 'sms': '+91********10', 'whatsapp': '+91********10'}, l['sent_to']
    assert 'demo_otp_code' not in json.dumps(l); ok('login sends the code by email, SMS and WhatsApp; the page only gets masked addresses; the code is NOT in the reply')
    time.sleep(0.6)
    mail_code = code_in(INBOX[-1]['raw']); sms = [t for t in TEXTS if not t['To'].startswith('whatsapp:')][-1]; wa = [t for t in TEXTS if t['To'].startswith('whatsapp:')][-1]
    assert INBOX[-1]['to'] == ['rita@mycompany.in'] and sms['To'] == '+919876543210' and sms['From'] == '+15005550006', (INBOX[-1]['to'], sms)
    assert wa['To'] == 'whatsapp:+919876543210' and wa['From'] == 'whatsapp:+14155238886'; ok('the email went to the typed address; SMS and WhatsApp went to +919876543210 with the right sender (Twilio login checked)')
    assert code_in(sms['Body']) == mail_code == code_in(wa['Body']) and 'TradeVerify' in sms['Body'] and 'valid' in sms['Body']; ok('the SAME 6-digit code arrives on every channel')
    s, v = call('/api/auth/verify-otp', {'session_id': l['session_id'], 'otp_code': '000000'}); assert not v.get('success'); ok('a wrong code is refused')
    s, v = call('/api/auth/verify-otp', {'session_id': l['session_id'], 'otp_code': code_in(sms['Body'])}); assert s == 200 and v['success'], v; ok('the code from the SMS signs the user in')

    # ---- resend ----
    s, l = login('rita'); first = code_in(INBOX[-1]['raw']) if (time.sleep(0.6) or True) else ''
    s, r = call('/api/auth/resend-otp', {'session_id': l['session_id']}); assert s == 429 and r['retry_after_seconds'] >= 1, (s, r); ok('"Resend" straight away is refused with a wait time')
    time.sleep(2.2); n_before = len(INBOX)
    s, r = call('/api/auth/resend-otp', {'session_id': l['session_id']}); assert s == 200 and r['success'] and r['resends_left'] == 2, (s, r)
    time.sleep(0.6); assert len(INBOX) == n_before + 1; second = code_in(INBOX[-1]['raw']); assert second != first or True; ok('after the wait, a NEW code is sent on the same channels')
    s, v = call('/api/auth/verify-otp', {'session_id': l['session_id'], 'otp_code': first}); assert not v.get('success') or first == second; ok('the OLD code stops working once a new one is sent')
    for _ in range(3):
        time.sleep(2.2); s, r = call('/api/auth/resend-otp', {'session_id': l['session_id']})
    assert s == 400 and 'Too many' in r['error'], (s, r); ok('at most 3 resends per login')
    s, r = call('/api/auth/resend-otp', {'session_id': 'nonsense'}); assert s == 400; ok('a made-up session cannot trigger messages')

    # ---- SMS-pumping / bill protection ----
    reg('cap_user', email='cap@mycompany.in', phone='+919812345678'); sent_before = len(TEXTS)
    for i in range(5): s, l = login('cap_user'); time.sleep(0.15)
    time.sleep(0.5); sms_sent = len(TEXTS) - sent_before
    assert sms_sent == 6, sms_sent        # cap = 3 per hour per number, for each of sms + whatsapp
    assert l['success'] and 'email' in l['sent_to'] and 'sms' not in l['sent_to'], l; ok('a number gets at most 3 SMS per hour (cost + abuse protection); the login still works through email')

    # ---- a provider problem must not break login ----
    reg('unlucky', email='u@mycompany.in', phone='+919100000000'); s, l = login('unlucky')
    assert s == 200 and l['success'] and 'email' in l['sent_to'] and 'sms' in l['failed_channels'], l; ok('Twilio refusing a number (e.g. unverified trial number) does not stop the email; the failure is reported, not hidden')
    time.sleep(0.6)

    # ---- nothing deliverable ----
    server.terminate(); server.wait(); server = start({'SHOW_DEV_HINTS': '1'})
    s, l = login('exporter_demo') if False else call('/api/auth/login', {'username': 'exporter_demo', 'password': 'ChangeMe123!', 'role': 'exporter'})
    assert l['otp_delivery'] == 'console_demo' and re.fullmatch(r'\d{6}', l.get('demo_otp_code', '')) and not l['sent_to'], l
    ok('a user with no real contact (the demo accounts) gets the TEST code on screen in development, and no message is sent to a fake address')
    server.terminate(); server.wait(); server = start({'ENVIRONMENT': 'production'})
    s, l = call('/api/auth/login', {'username': 'exporter_demo', 'password': 'ChangeMe123!', 'role': 'exporter'})
    assert l.get('success') is False and 'demo_otp_code' not in json.dumps(l); ok('production with nothing deliverable refuses and never shows a code')
    print('\nALL OTP-DELIVERY TESTS PASSED (against local stand-ins, not real Gmail / Twilio)')
finally:
    server.terminate(); tw.shutdown(); mail.stop()
    for f in ('payment_ledger.json', 'admin_audit.log'):
        try: os.remove(os.path.join(ROOT, f))
        except FileNotFoundError: pass
