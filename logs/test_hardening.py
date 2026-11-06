"""Tests for v35: block alerts, email codes (production-safe), CORS, security headers, rate limits, real client IP."""
import http.server, json, os, sys, threading, time, logging
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import account_scout as S, alerts as A, security as X, auth_engine as AU, account_unlock as U

def ok(m): print('ok ', m)
def env(**kw):
    for k, v in kw.items():
        if v is None: os.environ.pop(k, None)
        else: os.environ[k] = v

# ---------- real client IP ----------
assert X.resolve_client_ip('203.0.113.9', '1.2.3.4', trusted=set()) == '203.0.113.9'
ok('X-Forwarded-For from an unknown sender is ignored (cannot be spoofed)')
T = {'10.0.0.5'}
assert X.resolve_client_ip('10.0.0.5', '198.51.100.7', T) == '198.51.100.7'
assert X.resolve_client_ip('10.0.0.5', '6.6.6.6, 198.51.100.7', T) == '198.51.100.7'
ok('behind our proxy the real customer address is used, and a forged left-hand entry does not win')
assert X.resolve_client_ip('10.0.0.5', 'not-an-ip', T) == '10.0.0.5'; ok('a malformed header is not trusted')

# ---------- CORS ----------
env(ENVIRONMENT='production', ALLOWED_ORIGINS=None)
assert X.cors_origin('https://evil.example') is None; ok('production default: no cross-origin access')
env(ALLOWED_ORIGINS='https://app.example.com')
assert X.cors_origin('https://app.example.com') == 'https://app.example.com' and X.cors_origin('https://evil.example') is None
ok('only listed origins are allowed, and the exact origin is echoed (never *)')
env(ENVIRONMENT='development', ALLOWED_ORIGINS=None)
assert X.cors_origin('http://localhost:8080') == '*'; ok('development keeps the old open behaviour')

# ---------- security headers ----------
names = {h for h, _ in X.security_headers(False)}
assert {'X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy', 'Content-Security-Policy-Report-Only'} <= names
assert 'Strict-Transport-Security' not in names; ok('headers are set; the CSP is report-only by default so no page breaks')
env(CSP_ENFORCE='1', HSTS='1')
names = {h for h, _ in X.security_headers(True)}
assert 'Content-Security-Policy' in names and 'Strict-Transport-Security' in names; ok('CSP_ENFORCE=1 enforces it, HSTS only over https')
env(CSP_ENFORCE=None, HSTS=None)

# ---------- rate limits ----------
X.reset_rate_limits(); now = time.time()
res = [X.rate_limited('/api/auth/login', '1.1.1.1', now + i * 0.1) for i in range(12)]
assert res[:10] == [0] * 10 and res[10] > 0 and res[11] > 0, res; ok('login: 10 per minute per address, then refused with a wait time')
assert X.rate_limited('/api/auth/login', '2.2.2.2', now + 2) == 0; ok('another address is not affected')
assert X.rate_limited('/api/auth/login', '1.1.1.1', now + 70) == 0; ok('the allowance returns after the window')
assert X.rate_limited('/index.html', '1.1.1.1', now) == 0; ok('ordinary pages are not limited')
admin = [X.rate_limited('/api/admin/blocks', '3.3.3.3', now + i * 0.01) for i in range(45)]
assert admin[39] == 0 and admin[40] > 0; ok('every /api/admin/ call is covered (password guessing is slowed down)')

# ---------- alerts: real HTTP POST to a local sink ----------
got = []
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        got.append(json.loads(self.rfile.read(int(self.headers['Content-Length'])))); self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
srv = http.server.HTTPServer(('127.0.0.1', 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
env(ALERT_WEBHOOK_URL=f'http://127.0.0.1:{srv.server_port}/hook', ALERT_EMAIL_TO=None, PUBLIC_BASE_URL='https://pay.example.com')
A._SEEN_REFS.clear(); A._LAST_FOR_ACCOUNT.clear(); A._RECENT.clear(); A.SENT_LOG.clear(); S._BLOCK_HISTORY.clear()
t0 = time.time(); acct = 'exporter:alert_user'
for k in ('session:s1', f'account:{acct}', 'card:fp1'):
    S._block_key(k, t0, 'carding', '4 failed payments', acct)
for _ in range(50):
    if got: break
    time.sleep(0.05)
assert len(got) == 1, got; text = got[0]['text']
assert 'CARD TESTING SUSPECTED' in text and 'Reference: TV-' in text and acct in text and 'https://pay.example.com/admin.html' in text, text
assert 'fp1' not in text and '4242' not in text; ok('a block sends exactly ONE Slack-style alert (not one per blocked key), with reference, account and admin link')
# repeat block of the same account within a minute: no second message; a manual-review lock still gets through
S.unblock(f'account:{acct}'); S.unblock('session:s1'); S.unblock('card:fp1')
S._block_key(f'account:{acct}', t0 + 5, 'carding', 'again', acct); time.sleep(0.3)
assert len(got) == 1; ok('the same account again within a minute does not flood the channel')
S.unblock(f'account:{acct}'); S._block_key(f'account:{acct}', t0 + 8, 'carding', 'third', acct)
for _ in range(50):
    if len(got) > 1: break
    time.sleep(0.05)
assert len(got) == 2 and 'URGENT' in got[1]['text'] and 'MANUAL REVIEW' in got[1]['text'], got
ok('a level-3 (manual review) lock is sent as URGENT even inside the quiet period')
# a dead webhook must never break or slow the block
env(ALERT_WEBHOOK_URL='http://127.0.0.1:1/dead'); S.unblock(f'account:{acct}')
s = time.time(); S._block_key('account:exporter:other', time.time(), 'bot', 'x', 'exporter:other'); assert time.time() - s < 0.5
ok('a broken alert destination cannot fail or delay a block')
env(ALERT_WEBHOOK_URL=None); assert not A.enabled(); ok('no destination configured = alerts quietly off')

# ---------- email codes ----------
sent = []
class FakeSMTP:
    def __init__(self, host, port, timeout=0): sent.append(('connect', host, port))
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def starttls(self): sent.append(('starttls',))
    def login(self, u, p): sent.append(('login', u))
    def sendmail(self, frm, to, msg): sent.append(('mail', to, msg))
AU.smtplib.SMTP = FakeSMTP
AU.SMTP_CONFIGURED, AU.SMTP_HOST, AU.SMTP_PORT, AU.SMTP_USER, AU.SMTP_PASSWORD, AU.SMTP_FROM = True, 'smtp.test', 587, 'u', 'p', 'noreply@test'
assert AU._send_otp('sneha', 'sneha@mycompany.in', '123456', 'login') == 'email'
mail = [m for m in sent if m[0] == 'mail'][-1]; assert 'login code' in mail[2] and '123456' in mail[2] and ('starttls',) in sent
ok('login code is emailed over STARTTLS')
sent.clear(); assert AU._send_otp('sneha', 'sneha@mycompany.in', '654321', 'unlock') == 'email'
mail = [m for m in sent if m[0] == 'mail'][-1]; assert 'unblock code' in mail[2] and '654321' in mail[2]
ok('the unblock email has its own wording')
# production: no SMTP -> the code must not reach the browser or the log
AU.SMTP_CONFIGURED = False; env(ENVIRONMENT='production')
class Cap(logging.Handler):
    def __init__(self): super().__init__(); self.lines = []
    def emit(self, r): self.lines.append(r.getMessage())
cap = Cap(); logging.getLogger('auth_engine').addHandler(cap)
AU.register_user('prod_user', 'Passw0rd!x1', 'exporter', 'p@mycompany.in')
r = AU.login_password_step('prod_user', 'Passw0rd!x1', 'exporter')
assert r['success'] is False and 'demo_otp_code' not in r and not AU._PENDING_OTPS, r
ok('production without email: login fails closed, no code in the response')
import re
assert not any(re.search(r'\b\d{6}\b', l) for l in cap.lines if 'OTP' in l), cap.lines
assert any('hidden in production' in l for l in cap.lines); ok('...and the code is not written to the log either')
env(ENVIRONMENT='development')
r = AU.login_password_step('prod_user', 'Passw0rd!x1', 'exporter'); assert r['success'] and r.get('demo_otp_code'); ok('development still shows the code for local testing')
# unlock in production without email
env(ENVIRONMENT='production')
acct2 = 'exporter:unlock_prod'; AU._USERS[acct2] = {'username': 'unlock_prod', 'role': 'exporter', 'email': 'x@mycompany.in'}
S._BLOCK_HISTORY.pop(acct2, None); S._block_key(f'account:{acct2}', time.time(), 'carding', 't', acct2)
r = U.request_unlock(acct2); assert not r['success'] and 'demo_otp_code' not in r and acct2 not in U._PENDING, r
ok('unblock code in production without email: refused, nothing stored, nothing shown')
print('\nALL HARDENING TESTS PASSED')
