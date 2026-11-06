"""
Sends the one-time code to the customer by EMAIL, SMS or WhatsApp (SMS and WhatsApp through Twilio's plain REST API,
so no extra library is needed). Used for the login code and for the "unblock my account" code.

  OTP_CHANNELS=email,sms,whatsapp   the code goes to every listed channel that is configured AND that the user gave
  email:     SMTP_HOST, SMTP_USER, SMTP_PASSWORD  (see auth_engine)
  sms:       SMS_PROVIDER=twilio, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_FROM or TWILIO_MESSAGING_SERVICE_SID
  whatsapp:  the same Twilio keys + WHATSAPP_FROM=whatsapp:+14155238886
  DEFAULT_PHONE_COUNTRY_CODE=+91    for numbers typed without a country code

The code itself is NEVER returned from here, logged in production, or written into any result.
"""
import base64
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

_LOG = logging.getLogger('otp_delivery')
_LOCK = threading.Lock()
_SENDS = {}          # (channel, recipient) -> [timestamps]   (in memory, per process)

SMS_TEXT = {
    'login': '{code} is your TradeVerify AI login code. It is valid for {mins} minutes. Do not share it with anyone.',
    'unlock': '{code} is your TradeVerify AI code to unblock payments. It is valid for {mins} minutes. Do not share it.',
}


# ------------------------------------------------------------------ phone numbers
def normalize_phone(raw, default_cc=None):
    """'+919876543210' / '98765 43210' / '098765-43210' -> '+919876543210'; '' when it cannot be a real number."""
    s = str(raw or '').strip()
    if not s:
        return ''
    plus = s.startswith('+')
    digits = re.sub(r'\D', '', s)
    if not digits:
        return ''
    if plus:
        out = '+' + digits
    elif s.startswith('00') and len(digits) > 4:
        out = '+' + digits[2:]
    else:
        cc = re.sub(r'\D', '', default_cc or os.environ.get('DEFAULT_PHONE_COUNTRY_CODE', '+91'))
        out = '+' + cc + digits.lstrip('0')
    return out if re.fullmatch(r'\+[1-9]\d{7,14}', out) else ''


def mask_phone(e164):
    return (e164[:3] + '*' * max(0, len(e164) - 5) + e164[-2:]) if e164 else ''


def mask_email(email):
    local, _, domain = str(email or '').partition('@')
    return (local[:1] + '***@' + domain) if domain else ''


# ------------------------------------------------------------------ configuration
def configured_channels():
    """Channels that are both switched on in OTP_CHANNELS and properly configured."""
    wanted = [c.strip().lower() for c in os.environ.get('OTP_CHANNELS', 'email,sms').split(',') if c.strip()]
    out = []
    if 'email' in wanted and _email_configured():
        out.append('email')
    if 'sms' in wanted and _twilio_configured() and (os.environ.get('TWILIO_FROM', '').strip() or os.environ.get('TWILIO_MESSAGING_SERVICE_SID', '').strip()):
        out.append('sms')
    if 'whatsapp' in wanted and _twilio_configured() and os.environ.get('WHATSAPP_FROM', '').strip():
        out.append('whatsapp')
    return out


def _email_configured():
    import auth_engine
    return bool(auth_engine.SMTP_CONFIGURED)


def _twilio_configured():
    return (os.environ.get('SMS_PROVIDER', 'twilio').strip().lower() == 'twilio'
            and bool(os.environ.get('TWILIO_ACCOUNT_SID', '').strip()) and bool(os.environ.get('TWILIO_AUTH_TOKEN', '').strip()))


def channels_for_user(user):
    """Configured channels that this user can actually receive (has an email / a mobile number for)."""
    from auth_engine import _is_placeholder_email
    out = []
    for ch in configured_channels():
        if ch == 'email' and user.get('email') and not _is_placeholder_email(user['email']):
            out.append(ch)
        elif ch in ('sms', 'whatsapp') and user.get('phone'):
            out.append(ch)
    return out


# ------------------------------------------------------------------ abuse limits (SMS pumping / bill protection)
def _allowed(channel, recipient, now):
    cap = int(os.environ.get('OTP_MAX_EMAIL_PER_ADDRESS_PER_HOUR', '10')) if channel == 'email' else int(os.environ.get('OTP_MAX_SMS_PER_NUMBER_PER_HOUR', '5'))
    with _LOCK:
        q = [t for t in _SENDS.get((channel, recipient), []) if now - t < 3600]
        if len(q) >= cap:
            _SENDS[(channel, recipient)] = q
            return False
        q.append(now)
        _SENDS[(channel, recipient)] = q
        if len(_SENDS) > 20000:
            _SENDS.clear()
    return True


def reset_limits():
    with _LOCK:
        _SENDS.clear()


# ------------------------------------------------------------------ Twilio
def _twilio_send(to, body, whatsapp=False):
    sid = os.environ.get('TWILIO_ACCOUNT_SID', '').strip()
    token = os.environ.get('TWILIO_AUTH_TOKEN', '').strip()
    base = os.environ.get('TWILIO_API_BASE', 'https://api.twilio.com').rstrip('/')
    fields = {'To': ('whatsapp:' + to) if whatsapp else to, 'Body': body}
    if whatsapp:
        fields['From'] = os.environ.get('WHATSAPP_FROM', '').strip()
    elif os.environ.get('TWILIO_MESSAGING_SERVICE_SID', '').strip():
        fields['MessagingServiceSid'] = os.environ['TWILIO_MESSAGING_SERVICE_SID'].strip()
    else:
        fields['From'] = os.environ.get('TWILIO_FROM', '').strip()
    req = urllib.request.Request(f'{base}/2010-04-01/Accounts/{sid}/Messages.json', urllib.parse.urlencode(fields).encode('utf-8'),
                                 {'Authorization': 'Basic ' + base64.b64encode(f'{sid}:{token}'.encode()).decode(),
                                  'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode('utf-8') or '{}')
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode('utf-8')).get('message', '')
        except Exception:
            detail = ''
        raise RuntimeError(detail or f'Twilio refused the message (HTTP {e.code}).')
    except Exception as e:
        raise RuntimeError(f'Could not reach Twilio: {e}')


# ------------------------------------------------------------------ the main entry point
def send(user, code, purpose='login', now=None):
    """
    Send `code` on every channel this user can receive. Returns
      {'sent': [channels that went out], 'failed': {channel: short reason}, 'hints': {channel: masked address},
       'delivery': 'email' | 'sms' | 'whatsapp' | 'email+sms' | ... | 'none'}
    'none' means nothing could be sent (nothing configured, no contact details, or every send failed); the caller then
    decides what to do (development: show the test code; production: refuse). The code is never part of the result.
    """
    import auth_engine
    now = now if now is not None else time.time()
    mins = auth_engine.OTP_TTL_SEC // 60
    out = {'sent': [], 'failed': {}, 'hints': {}, 'delivery': 'none'}
    for ch in channels_for_user(user):
        try:
            if ch == 'email':
                if not _allowed('email', user['email'].lower(), now):
                    out['failed']['email'] = 'too many codes sent to this address; try later'; continue
                if auth_engine._send_otp(user.get('username', ''), user['email'], code, purpose) != 'email':
                    out['failed']['email'] = 'the email could not be sent'; continue
                out['hints']['email'] = mask_email(user['email'])
            else:
                if not _allowed(ch, user['phone'], now):
                    out['failed'][ch] = 'too many codes sent to this number; try later'; continue
                text = SMS_TEXT.get(purpose, SMS_TEXT['login']).format(code=code, mins=mins)
                _twilio_send(user['phone'], text, whatsapp=(ch == 'whatsapp'))
                out['hints'][ch] = mask_phone(user['phone'])
            out['sent'].append(ch)
        except Exception as e:                       # never let a provider problem crash a login
            out['failed'][ch] = str(e)[:140]
            _LOG.warning('otp_delivery: %s send failed (%s)', ch, e)
    if out['sent']:
        out['delivery'] = '+'.join(out['sent'])
    return out


def send_test(channel, to):
    """For check_otp_delivery.py: one clearly-labelled test message (no real code)."""
    import auth_engine
    channel = channel.lower()
    if channel == 'email':
        if not auth_engine.SMTP_CONFIGURED:
            raise RuntimeError('Email is not configured: set SMTP_HOST, SMTP_USER and SMTP_PASSWORD in otp_settings.env.')
        msg = auth_engine.MIMEText('If you can read this, TradeVerify can email one-time codes.')
        msg['Subject'], msg['From'], msg['To'] = 'TradeVerify delivery test', auth_engine.SMTP_FROM, to
        with auth_engine.smtplib.SMTP(auth_engine.SMTP_HOST, auth_engine.SMTP_PORT, timeout=15) as s:
            s.starttls(); s.login(auth_engine.SMTP_USER, auth_engine.SMTP_PASSWORD); s.sendmail(auth_engine.SMTP_FROM, [to], msg.as_string())
        return 'Test email sent. Check the inbox and the spam folder.'
    if channel in ('sms', 'whatsapp'):
        if channel not in configured_channels():
            raise RuntimeError(f'{channel} is not configured: check the Twilio settings and OTP_CHANNELS in otp_settings.env.')
        phone = normalize_phone(to)
        if not phone:
            raise RuntimeError('That does not look like a mobile number. Use the form +919876543210.')
        _twilio_send(phone, 'TradeVerify delivery test: if you can read this, one-time codes can reach you.', whatsapp=(channel == 'whatsapp'))
        return f'Test {channel} message sent to {mask_phone(phone)}.'
    raise RuntimeError('Channel must be email, sms or whatsapp.')
