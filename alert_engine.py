#!/usr/bin/env python3
"""
alert_engine.py — Real-time fraud alerting (email + Slack)
-------------------------------------------------------------
Fires the moment the fraud engine actually blocks something (a card, an
account, a session) — not on every check, only on the transition into a
block, so this doesn't spam on every subsequent already-blocked request.

Two channels, both optional, both fail safe (logs instead of crashing if
unconfigured or if sending fails):

  EMAIL — reuses the same SMTP settings auth_engine.py uses for OTP:
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM
    Plus one more, specific to alerts:
    ALERT_EMAIL_TO — who receives fraud alerts (not the customer; your
    security/admin inbox). Comma-separated for multiple recipients.

  SLACK — a Slack Incoming Webhook URL:
    ALERT_SLACK_WEBHOOK_URL

If neither is configured, alerts are still logged to the console at WARNING
level, so nothing is silently lost — it just doesn't reach anyone outside
the terminal until one of these is set up.
"""

import os
import json
import smtplib
import logging
import urllib.request
from email.mime.text import MIMEText
from datetime import datetime, timezone

_LOG = logging.getLogger("alert_engine")

SMTP_HOST = os.environ.get('SMTP_HOST', '').strip()
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '').strip()
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '').strip()
SMTP_FROM = os.environ.get('SMTP_FROM', '').strip() or SMTP_USER
SMTP_CONFIGURED = bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD)

ALERT_EMAIL_TO = [e.strip() for e in os.environ.get('ALERT_EMAIL_TO', '').split(',') if e.strip()]
ALERT_SLACK_WEBHOOK_URL = os.environ.get('ALERT_SLACK_WEBHOOK_URL', '').strip()

_CONFIGURED_CHANNELS = []
if SMTP_CONFIGURED and ALERT_EMAIL_TO:
    _CONFIGURED_CHANNELS.append('email')
if ALERT_SLACK_WEBHOOK_URL:
    _CONFIGURED_CHANNELS.append('slack')

if not _CONFIGURED_CHANNELS:
    _LOG.warning("alert_engine: no alert channel configured (set ALERT_EMAIL_TO + SMTP_* for "
                 "email, or ALERT_SLACK_WEBHOOK_URL for Slack) — fraud blocks will only be "
                 "logged to this console, nobody gets notified externally.")
else:
    _LOG.warning("alert_engine: alerting active via: %s", ', '.join(_CONFIGURED_CHANNELS))


def _send_email_alert(subject: str, body: str) -> bool:
    if not (SMTP_CONFIGURED and ALERT_EMAIL_TO):
        return False
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_FROM
    msg['To'] = ', '.join(ALERT_EMAIL_TO)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, ALERT_EMAIL_TO, msg.as_string())
        return True
    except Exception as e:
        _LOG.error("alert_engine: failed to send email alert: %s", e)
        return False


def _send_slack_alert(text: str) -> bool:
    if not ALERT_SLACK_WEBHOOK_URL:
        return False
    try:
        payload = json.dumps({'text': text}).encode('utf-8')
        req = urllib.request.Request(
            ALERT_SLACK_WEBHOOK_URL, data=payload,
            headers={'Content-Type': 'application/json'}, method='POST'
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        _LOG.error("alert_engine: failed to send Slack alert: %s", e)
        return False


def send_block_alert(block_type: str, key: str, details: str, account_id: str = '') -> dict:
    """
    block_type: 'carding' | 'bot' — what kind of detection triggered this.
    key: the specific key that got blocked (e.g. "card:xxxx", "account:exporter:demo").
    details: the human-readable explanation already produced by the detector.
    account_id: the account this ties to, if known.
    Returns which channels actually delivered, for logging/debugging.
    """
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    subject = f"🚨 TradeVerify Fraud Alert: {block_type.upper()} block — {key}"
    body = (
        f"A fraud block was just triggered on TradeVerify AI.\n\n"
        f"Type:       {block_type}\n"
        f"Blocked key: {key}\n"
        f"Account:     {account_id or 'n/a'}\n"
        f"Time:        {now}\n\n"
        f"Details: {details}\n\n"
        f"Review or clear this block at /admin.html if it's a false positive."
    )
    slack_text = (
        f":rotating_light: *TradeVerify Fraud Alert* — *{block_type.upper()}*\n"
        f"> Blocked: `{key}`\n"
        f"> Account: `{account_id or 'n/a'}`\n"
        f"> {details}\n"
        f"> Time: {now}"
    )

    delivered = []
    if _send_email_alert(subject, body):
        delivered.append('email')
    if _send_slack_alert(slack_text):
        delivered.append('slack')

    if not delivered:
        _LOG.warning("alert_engine [NO CHANNEL DELIVERED]: %s block on %s — %s", block_type, key, details)

    return {'delivered': delivered}
