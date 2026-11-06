#!/usr/bin/env python3
"""
auth_engine.py — Exporter & Importer Login with Adaptive MFA
--------------------------------------------------------------
Completes the account-security workstream by giving it an actual front door:
two login flows (exporter, importer), each password-protected and backed by
OTP-based MFA, with every login attempt run through the fraud/security engine
already built in account_scout.py:
  - Problem 6 (Haversine impossible travel) checked on every password success
  - Problem 5 (adaptive step-up) decides whether OTP alone is enough, or the
    login gets blocked outright, based on combined risk signal

USER STORE:
In-memory + salted-hash, for demo/PoC purposes (2 seed users below). Swap
`_USERS` for a real database before production — passwords should never
live only in process memory, and a restart currently forgets every account.

OTP DELIVERY:
No real SMS/email gateway is wired up, so generated OTPs are logged to the
server console (clearly marked DEMO) and also returned in the login response
for local testing. Replace `_send_otp` with a real provider before this ever
handles a real user.
"""

import os
import re
import time
import hashlib
import hmac as _hmac
import secrets
import logging
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timezone

from account_scout import (
    record_login_event, record_otp_attempt, evaluate_adaptive_step_up, get_account_risk
)

_LOG = logging.getLogger("auth_engine")

OTP_TTL_SEC = int(os.environ.get('AUTH_OTP_TTL_SEC', 300))
SESSION_TTL_SEC = int(os.environ.get('AUTH_SESSION_TTL_SEC', 8 * 3600))
PBKDF2_ITERATIONS = 200_000

VALID_ROLES = ('exporter', 'importer')

# --------------------------------------------------------------------------- #
# Real OTP delivery via email (SMTP). Configure these env vars to actually
# send the code instead of only logging it to the console:
#   SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASSWORD
#   SMTP_FROM (default: SMTP_USER)
# Works with Gmail (use an App Password, not your normal password), Outlook,
# SendGrid's SMTP relay, or any standard SMTP server.
# If these aren't set, or the send fails, this falls back to logging the code
# to the server console AND returning it in the API response — clearly
# labeled — so local testing still works without an email account configured.
# --------------------------------------------------------------------------- #

SMTP_HOST = os.environ.get('SMTP_HOST', '').strip()
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '').strip()
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '').strip()
SMTP_FROM = os.environ.get('SMTP_FROM', '').strip() or SMTP_USER
SMTP_CONFIGURED = bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD)

if not SMTP_CONFIGURED:
    _LOG.warning("auth_engine: SMTP not configured (SMTP_HOST/SMTP_USER/SMTP_PASSWORD unset) — "
                 "OTP codes will only be logged to this console, not actually emailed. "
                 "Set those env vars to send real emails.")


# --------------------------------------------------------------------------- #
# Password hashing (stdlib only, consistent with this project's 0-external-
# calls / fully offline design — no bcrypt/argon2 dependency required)
# --------------------------------------------------------------------------- #

def _hash_password(password: str, salt: bytes = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
    return f"{salt.hex()}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split('$')
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
        return _hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# In-memory user store — DEMO ONLY, see module docstring.
# --------------------------------------------------------------------------- #

_USERS = {}  # key: f"{role}:{username}" -> {username, role, password_hash, created_at}


def create_user(username: str, password: str, role: str, email: str = '', phone: str = '') -> dict:
    if role not in VALID_ROLES:
        raise ValueError(f"role must be one of {VALID_ROLES}")
    key = f"{role}:{username}"
    _USERS[key] = {
        'username': username,
        'role': role,
        'email': email,
        'phone': phone,
        'password_hash': _hash_password(password),
        'created_at': datetime.now(timezone.utc).isoformat(),
    }
    return {'username': username, 'role': role, 'email': email, 'phone': phone}


MIN_PASSWORD_LENGTH = int(os.environ.get('AUTH_MIN_PASSWORD_LENGTH', 8))


def register_user(username: str, password: str, role: str, email: str = '', phone: str = '') -> dict:
    """
    Public-facing signup — lets someone pick their own username/password
    instead of using the seeded demo account. Validates basic shape and
    rejects a username that's already taken for that role. Still the same
    in-memory store as everything else here (see module docstring) — accounts
    are lost on restart until this is backed by a real database.
    """
    username = (username or '').strip()
    if role not in VALID_ROLES:
        return {'success': False, 'error': f"role must be one of {VALID_ROLES}"}
    if not username or len(username) < 3:
        return {'success': False, 'error': 'Username must be at least 3 characters.'}
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return {'success': False, 'error': f'Password must be at least {MIN_PASSWORD_LENGTH} characters.'}
    if f"{role}:{username}" in _USERS:
        return {'success': False, 'error': 'That username is already taken for this role.'}

    import otp_delivery
    email = (email or '').strip()
    if email and not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email):
        return {'success': False, 'error': 'Enter a valid email address.'}
    phone_n = ''
    if str(phone or '').strip():
        phone_n = otp_delivery.normalize_phone(phone)
        if not phone_n:
            return {'success': False, 'error': 'Enter the mobile number with its country code, for example +919876543210.'}
    if otp_delivery.configured_channels() and not (email or phone_n):
        return {'success': False, 'error': 'Add an email address or a mobile number so we can send your login code.'}

    create_user(username, password, role, email=email, phone=phone_n)
    _LOG.info("auth_engine: new account registered — role=%s username=%s", role, username)
    return {'success': True, 'username': username, 'role': role}


def _demo_phone(raw):
    import otp_delivery
    return otp_delivery.normalize_phone(raw) if raw else ''


def _seed_demo_users():
    if not _USERS:
        # Point these at a real inbox you control (via env vars) to actually
        # receive the OTP emails during testing — otherwise they default to
        # placeholder addresses that won't receive anything.
        exp_email = os.environ.get('DEMO_EXPORTER_EMAIL', 'exporter_demo@example.com')
        imp_email = os.environ.get('DEMO_IMPORTER_EMAIL', 'importer_demo@example.com')
        exp_phone = os.environ.get('DEMO_EXPORTER_PHONE', '')
        imp_phone = os.environ.get('DEMO_IMPORTER_PHONE', '')
        # Override the seeded demo password via env vars if you'd rather not
        # use the default — or just use /api/auth/register to create a
        # brand new account with whatever username/password you want instead.
        exp_pw = os.environ.get('DEMO_EXPORTER_PASSWORD', 'ChangeMe123!')
        imp_pw = os.environ.get('DEMO_IMPORTER_PASSWORD', 'ChangeMe123!')
        create_user('exporter_demo', exp_pw, 'exporter', email=exp_email, phone=_demo_phone(exp_phone))
        create_user('importer_demo', imp_pw, 'importer', email=imp_email, phone=_demo_phone(imp_phone))
        _LOG.warning("auth_engine: seeded DEMO accounts exporter_demo (%s) / importer_demo (%s) — "
                     "remove before real use. Set DEMO_EXPORTER_PASSWORD / DEMO_IMPORTER_PASSWORD "
                     "to change their passwords, or use /api/auth/register to create your own account.",
                     exp_email, imp_email)


_seed_demo_users()


# --------------------------------------------------------------------------- #
# In-memory OTP + session state — DEMO ONLY (swap for Redis/DB alongside the
# user store above before production; same reasoning as account_scout.py's
# store, see PRODUCTION_READINESS.md).
# --------------------------------------------------------------------------- #

_PENDING_OTPS = {}   # session_id -> {code, username, role, expires_at, geo_result}
_SESSIONS = {}        # token -> {username, role, expires_at}


_OTP_EMAILS = {
    'login': ("Your TradeVerify AI login code",
              "Your one-time login code is: {code}\n\nThis code expires in {mins} minutes. "
              "If you didn't try to log in, you can ignore this email."),
    'unlock': ("Your TradeVerify AI unblock code",
               "Your one-time code to unblock payments on your account is: {code}\n\nThis code expires in {mins} minutes. "
               "If you didn't ask for this, someone may be trying to use your account: ignore this email and contact support."),
}


def _is_placeholder_email(email: str) -> bool:
    """Reserved example addresses (RFC 2606) never receive mail."""
    domain = str(email or '').rsplit('@', 1)[-1].strip().lower()
    return domain in ('example.com', 'example.net', 'example.org') or domain.rsplit('.', 1)[-1] in ('test', 'example', 'invalid', 'localhost')


def _send_otp(username: str, email: str, code: str, purpose: str = 'login') -> str:
    """
    Sends the OTP by real email when SMTP is configured; otherwise falls back
    to logging it to the console. Returns 'email' or 'console_fallback' /
    'console_demo' so the caller knows whether it's safe to omit the code
    from the API response.
    In production the code is NEVER written to the log: a log file is not a safe place for a login code.
    """
    from security import is_production
    shown = '(hidden in production)' if is_production() else code
    if not SMTP_CONFIGURED:
        _LOG.warning("auth_engine [NO SMTP CONFIGURED — code not emailed]: "
                     "OTP for %s is %s (expires in %ss)", username, shown, OTP_TTL_SEC)
        return 'console_demo'

    if not email or _is_placeholder_email(email):
        _LOG.warning("auth_engine: SMTP is configured but user %s has no real email on file — "
                     "falling back to console. OTP is %s", username, shown)
        return 'console_demo'

    subject, template = _OTP_EMAILS.get(purpose, _OTP_EMAILS['login'])
    body = template.format(code=code, mins=OTP_TTL_SEC // 60)
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_FROM
    msg['To'] = email

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, [email], msg.as_string())
        _LOG.info("auth_engine: OTP email sent to %s for user %s", email, username)
        return 'email'
    except Exception as e:
        _LOG.error("auth_engine: FAILED to send OTP email to %s (%s) — falling back to console. "
                    "OTP is %s", email, e, shown)
        return 'console_fallback'


def login_password_step(username: str, password: str, role: str,
                         ip: str = '', lat: float = None, lon: float = None, region: str = '') -> dict:
    """
    Step 1 of login: verify the password, run the Haversine impossible-travel
    check (Problem 6) against this account's login history, and issue an OTP
    if the password is correct — sent by real email when SMTP is configured
    (see the SMTP_* env vars above), console-logged otherwise.
    """
    if role not in VALID_ROLES:
        return {'success': False, 'error': f"role must be one of {VALID_ROLES}"}

    key = f"{role}:{username}"
    user = _USERS.get(key)
    # Constant-time-ish: still hash-check against a dummy value on unknown
    # username so response timing doesn't reveal whether the account exists.
    password_ok = _verify_password(password, user['password_hash']) if user else _verify_password(password, _hash_password('dummy'))

    if not user or not password_ok:
        return {'success': False, 'error': 'Invalid username or password.'}

    geo_result = None
    if lat is not None and lon is not None:
        geo_result = record_login_event(account_id=key, lat=lat, lon=lon, region=region)
        if geo_result.get('status') == 'ALERT':
            _LOG.warning("auth_engine: impossible-travel flagged for %s: %s", key, geo_result['details'])

    # Checks whether this account currently has an active carding/bot block
    # from checkout activity (see account_scout.get_account_risk) — this is
    # the link between the carding-detection workstream and login MFA: an
    # attack on this account's checkout raises this account's login risk too,
    # even though checkout and login use completely different session_ids.
    carding_result = get_account_risk(account_id=key)
    if carding_result.get('status') == 'CARDING_RED_FLAG':
        _LOG.warning("auth_engine: login for %s carries an active carding flag: %s", key, carding_result['details'])

    session_id = secrets.token_urlsafe(24)
    otp_code = f"{secrets.randbelow(10**6):06d}"
    _PENDING_OTPS[session_id] = {
        'code': otp_code, 'username': username, 'role': role,
        'expires_at': time.time() + OTP_TTL_SEC, 'geo_result': geo_result,
        'carding_result': carding_result, 'sent_at': time.time(), 'resends': 0,
    }
    import otp_delivery
    res = otp_delivery.send(user, otp_code, 'login')
    err = _delivery_failure(res, user, otp_code, session_id, drop_pending=True)
    if err:
        return err
    return _otp_response(session_id, otp_code, res, geo_result, carding_result)


OTP_RESEND_SEC = int(os.environ.get('AUTH_OTP_RESEND_SEC', 30))
OTP_MAX_RESENDS = int(os.environ.get('AUTH_OTP_MAX_RESENDS', 3))


def _delivery_failure(res, user, otp_code, session_id, drop_pending):
    """Nothing could be delivered: production refuses (never hands the code to the browser); development logs it."""
    if res['sent']:
        return None
    from security import is_production
    if is_production():
        _LOG.warning("auth_engine: could not deliver the one-time code for %s (%s); OTP is (hidden in production)",
                     user.get('username'), '; '.join(f'{k}: {v}' for k, v in res['failed'].items()) or 'no delivery channel set up for this user')
        if drop_pending:
            _PENDING_OTPS.pop(session_id, None)
        return {'success': False, 'error': 'We could not send your one-time code. Please try again later or contact support.'}
    _LOG.warning("auth_engine [DEV, nothing delivered%s]: OTP for %s is %s (expires in %ss)",
                 (' - ' + '; '.join(f'{k}: {v}' for k, v in res['failed'].items())) if res['failed'] else ' - no email/SMS set up',
                 user.get('username'), otp_code, OTP_TTL_SEC)
    return None


def _otp_response(session_id, otp_code, res, geo_result, carding_result):
    from security import show_dev_hints
    response = {
        'success': True,
        'requires_otp': True,
        'session_id': session_id,
        'geo_audit': geo_result,
        'carding_audit': carding_result,
        # 'email', 'sms', 'whatsapp', 'email+sms' ... when really delivered; otherwise a development fallback label
        'otp_delivery': res['delivery'] if res['sent'] else ('console_fallback' if res['failed'] else 'console_demo'),
        'sent_to': res['hints'],                       # masked: {'email': 's***@gmail.com', 'sms': '+91******10'}
        'email_hint': res['hints'].get('email', ''),
        'failed_channels': sorted(res['failed']),
        'resend_seconds': OTP_RESEND_SEC,
    }
    # The raw code is only ever returned when NOTHING was delivered AND development hints are on.
    if not res['sent'] and show_dev_hints():
        response['demo_otp_code'] = otp_code
    return response


def resend_otp(session_id: str) -> dict:
    """'Send me a new code': new code, same channels. 30 s apart, at most 3 times; wrong-code attempts are NOT reset."""
    pending = _PENDING_OTPS.get(session_id)
    now = time.time()
    if not pending or now > pending['expires_at']:
        return {'success': False, 'error': 'This login has expired. Please sign in again.'}
    wait = OTP_RESEND_SEC - (now - pending.get('sent_at', 0))
    if wait > 0:
        return {'success': False, 'error': f'Please wait {int(wait) + 1} seconds before asking for another code.', 'retry_after_seconds': int(wait) + 1}
    if pending.get('resends', 0) >= OTP_MAX_RESENDS:
        return {'success': False, 'error': 'Too many codes requested. Please sign in again.'}
    user = _USERS.get(f"{pending['role']}:{pending['username']}") or {}
    code = f"{secrets.randbelow(10**6):06d}"
    import otp_delivery
    res = otp_delivery.send(user, code, 'login')
    err = _delivery_failure(res, user, code, session_id, drop_pending=False)
    if err:
        return err
    pending.update(code=code, expires_at=now + OTP_TTL_SEC, sent_at=now, resends=pending.get('resends', 0) + 1)
    out = _otp_response(session_id, code, res, pending.get('geo_result'), pending.get('carding_result'))
    out['resends_left'] = OTP_MAX_RESENDS - pending['resends']
    return out


def verify_otp_step(session_id: str, otp_code: str) -> dict:
    """
    Step 2 of login: check the submitted OTP via the same stateful, real
    OTP-failure tracker used elsewhere (Problem 5), combine it with the
    geo result from step 1 into an adaptive risk decision, and only issue a
    session token if that decision is ALLOW.
    """
    pending = _PENDING_OTPS.get(session_id)
    if not pending:
        return {'success': False, 'error': 'No pending login for this session (expired or invalid).'}

    if time.time() > pending['expires_at']:
        del _PENDING_OTPS[session_id]
        return {'success': False, 'error': 'OTP expired. Please log in again.'}

    otp_correct = _hmac.compare_digest(otp_code.strip(), pending['code'])
    otp_result = record_otp_attempt(session_id=session_id, success=otp_correct)
    step_up = evaluate_adaptive_step_up(otp_result=otp_result, geo_result=pending.get('geo_result'),
                                         carding_result=pending.get('carding_result'))

    if step_up['action'] == 'BLOCK':
        return {'success': False, 'blocked': True, 'otp_audit': otp_result,
                'step_up_audit': step_up, 'error': 'Login blocked due to elevated risk.'}

    if not otp_correct:
        return {'success': False, 'blocked': False, 'otp_audit': otp_result,
                'step_up_audit': step_up, 'error': 'Incorrect OTP.'}

    if step_up['action'] == 'STEP_UP_REQUIRED':
        # Correct OTP, but risk signals say one factor isn't enough — a real
        # deployment would prompt a second factor here (security question,
        # email confirmation link, etc.) instead of granting access outright.
        _acct_block = (pending.get('carding_result') or {})
        if _acct_block.get('status') == 'CARDING_RED_FLAG':
            _msg = ('This account has been blocked because it may be under attack by a bot (payments were submitted faster than a human can). Please contact your administrator to restore access.'
                    if _acct_block.get('block_type') == 'bot' else
                    'This account has been temporarily blocked after suspicious card activity. Please contact your administrator to restore access.')
            return {'success': False, 'blocked': True, 'step_up_required': True,
                    'otp_audit': otp_result, 'step_up_audit': step_up, 'error': _msg}
        return {'success': False, 'blocked': False, 'step_up_required': True,
                'otp_audit': otp_result, 'step_up_audit': step_up,
                'error': 'Additional verification required before access is granted.'}

    token = secrets.token_urlsafe(32)
    _SESSIONS[token] = {
        'username': pending['username'], 'role': pending['role'],
        'expires_at': time.time() + SESSION_TTL_SEC,
    }
    del _PENDING_OTPS[session_id]

    return {
        'success': True, 'token': token, 'username': pending['username'], 'role': pending['role'],
        'otp_audit': otp_result, 'step_up_audit': step_up,
    }


def verify_session(token: str) -> dict:
    """Validates a session token issued by verify_otp_step."""
    sess = _SESSIONS.get(token)
    if not sess:
        return {'valid': False, 'error': 'Invalid session token.'}
    if time.time() > sess['expires_at']:
        del _SESSIONS[token]
        return {'valid': False, 'error': 'Session expired.'}
    return {'valid': True, 'username': sess['username'], 'role': sess['role']}
