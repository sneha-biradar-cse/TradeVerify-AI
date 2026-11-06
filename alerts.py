"""
Block alerts: tell a human when the fraud engine blocks an account, so incidents are not found by accident.

  ALERT_WEBHOOK_URL=https://hooks.slack.com/services/...   Slack-style incoming webhook ({"text": ...}); works with Slack,
                                                           and with Mattermost / Rocket.Chat style endpoints
  ALERT_EMAIL_TO=security@example.com,fraud@example.com    uses the same SMTP_* settings as one-time codes
  PUBLIC_BASE_URL=https://pay.example.com                  used to put a link to the admin page in the message

One alert per incident (all keys blocked in one incident share a reference ID). Sending happens in a background
thread, so a slow or broken Slack/SMTP can never delay or fail a payment. No card data is ever included.
"""
import json
import logging
import os
import smtplib
import threading
import time
import urllib.request
from email.mime.text import MIMEText

import account_scout as _scout

_LOG = logging.getLogger('alerts')
_CFG = _scout.POLICY.get('alerts') or {}
_PER_ACCOUNT_GAP = _CFG.get('min_seconds_between_alerts_per_account', 60)
_MAX_PER_MINUTE = _CFG.get('max_alerts_per_minute', 20)

_LOCK = threading.Lock()
_SEEN_REFS = set()
_LAST_FOR_ACCOUNT = {}
_RECENT = []
SENT_LOG = []            # (channel, reference) of attempted sends; used by the tests and the admin to see what went out


def enabled():
    return bool(os.environ.get('ALERT_WEBHOOK_URL', '').strip() or os.environ.get('ALERT_EMAIL_TO', '').strip())


def build_message(key, meta):
    kind = {'bot': 'BOT ATTACK SUSPECTED', 'carding': 'CARD TESTING SUSPECTED'}.get(meta.get('type'), 'FRAUD BLOCK')
    level = int(meta.get('lock_level') or 1)
    urgent = bool(meta.get('needs_review'))
    head = ('URGENT - MANUAL REVIEW NEEDED: ' if urgent else ('REPEAT LOCK (level %d): ' % level if level > 1 else '')) + kind
    base = os.environ.get('PUBLIC_BASE_URL', '').strip().rstrip('/')
    lines = [f"[TradeVerify] {head}",
             f"Reference: {meta.get('reference', '')}",
             f"Account: {meta.get('account_id') or '(unknown)'}",
             f"Lock level: {level}" + (f" (about {round((meta.get('lock_seconds') or 0) / 60)} min)" if meta.get('lock_seconds') else ''),
             f"Why: {meta.get('reason', '')}"]
    if base:
        lines.append(f"Admin page: {base}/admin.html")
    return head, '\n'.join(lines)


def _post_webhook(url, text):
    req = urllib.request.Request(url, json.dumps({'text': text}).encode('utf-8'), {'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=5) as r:
        r.read()


def _send_email(recipients, subject, body):
    from auth_engine import SMTP_CONFIGURED, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM
    if not SMTP_CONFIGURED:
        raise RuntimeError('SMTP is not configured')
    msg = MIMEText(body)
    msg['Subject'], msg['From'], msg['To'] = subject, SMTP_FROM, ', '.join(recipients)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
        s.starttls()
        s.login(SMTP_USER, SMTP_PASSWORD)
        s.sendmail(SMTP_FROM, recipients, msg.as_string())


def _deliver(subject, text, reference):
    url = os.environ.get('ALERT_WEBHOOK_URL', '').strip()
    to = [x.strip() for x in os.environ.get('ALERT_EMAIL_TO', '').split(',') if x.strip()]
    if url:
        try:
            _post_webhook(url, text); SENT_LOG.append(('webhook', reference))
        except Exception as e:
            _LOG.warning('alerts: webhook failed (%s)', e)
    if to:
        try:
            _send_email(to, subject, text); SENT_LOG.append(('email', reference))
        except Exception as e:
            _LOG.warning('alerts: email failed (%s)', e)
    del SENT_LOG[:-200]


def notify_block(key, meta, now=None, background=True):
    """Called for every block. Sends at most one alert per incident; never raises, never blocks the caller."""
    try:
        if not enabled():
            return False
        ref = meta.get('reference') or key
        now = now if now is not None else time.time()
        with _LOCK:
            if ref in _SEEN_REFS:
                return False                          # the other keys of the same incident
            acct = meta.get('account_id') or key
            urgent = bool(meta.get('needs_review'))
            if not urgent and now - _LAST_FOR_ACCOUNT.get(acct, 0) < _PER_ACCOUNT_GAP:
                _SEEN_REFS.add(ref); return False       # same account again within a minute: one alert is enough
            _RECENT[:] = [t for t in _RECENT if now - t < 60]
            if not urgent and len(_RECENT) >= _MAX_PER_MINUTE:
                _SEEN_REFS.add(ref); return False       # flood guard (an attack across many accounts): urgent still goes out
            _SEEN_REFS.add(ref); _LAST_FOR_ACCOUNT[acct] = now; _RECENT.append(now)
            if len(_SEEN_REFS) > 5000:
                _SEEN_REFS.clear()
        subject, text = build_message(key, meta)
        if background:
            threading.Thread(target=_deliver, args=(subject, text, ref), daemon=True).start()
        else:
            _deliver(subject, text, ref)
        return True
    except Exception as e:                            # an alert must never break a payment
        _LOG.warning('alerts: could not queue alert (%s)', e)
        return False
