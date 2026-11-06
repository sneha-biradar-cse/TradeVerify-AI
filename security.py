"""
Web hardening helpers for server.py (CORS allow-list, security headers, rate limits, real client IP behind a proxy).
Everything is configured with environment variables or fraud_policy.json -> "rate_limits", and is safe by default.

  ENVIRONMENT=production          production mode (also the default when the variable is not set)
  ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com   browsers allowed to call the API from another origin
  TRUSTED_PROXIES=10.0.0.5,10.0.0.6   addresses of YOUR load balancer / reverse proxy (so the real customer IP is used)
  CSP_ENFORCE=1                   enforce the Content-Security-Policy (default: report-only, so nothing breaks)
  HSTS=1                          send Strict-Transport-Security (only turn on once the site is served over HTTPS)
  RATE_LIMIT_ENABLED=0            switch rate limiting off (default on)
"""
import ipaddress
import os
import threading
import time
from collections import defaultdict, deque

import account_scout as _scout

_DEV_NAMES = ('development', 'dev', 'test')


def is_production():
    return os.environ.get('ENVIRONMENT', 'production').strip().lower() not in _DEV_NAMES


# ---------------------------------------------------------------- client IP
def _split(name):
    return {x.strip() for x in os.environ.get(name, '').split(',') if x.strip()}


def resolve_client_ip(peer, forwarded_for, trusted=None):
    """
    The real customer address. X-Forwarded-For is only believed when the direct peer is one of OUR proxies
    (TRUSTED_PROXIES); then we walk the list from the right, skipping our own proxies, and take the first
    address that is not ours. Anyone else sending the header is ignored, so it cannot be spoofed.
    """
    trusted = _split('TRUSTED_PROXIES') if trusted is None else trusted
    if peer not in trusted or not forwarded_for:
        return peer
    hops = []
    for h in forwarded_for.split(','):
        h = h.strip()
        try:
            ipaddress.ip_address(h)
            hops.append(h)
        except ValueError:
            return peer                       # malformed header: do not trust any of it
    for h in reversed(hops):
        if h not in trusted:
            return h
    return hops[0] if hops else peer


# ---------------------------------------------------------------- CORS
def cors_origin(origin):
    """Value for Access-Control-Allow-Origin, or None (= send no CORS header, same-origin only)."""
    allowed = _split('ALLOWED_ORIGINS')
    if origin and origin in allowed:
        return origin
    if not is_production() and not allowed:
        return '*'                            # development convenience: unchanged behaviour
    return None


# ---------------------------------------------------------------- security headers
_CSP = ("default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com https://js.stripe.com https://challenges.cloudflare.com https://cdn.sheetjs.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: blob: https:; "
        "connect-src 'self' https://api.stripe.com https://challenges.cloudflare.com; "
        "frame-src https://js.stripe.com https://hooks.stripe.com https://challenges.cloudflare.com; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'")


def security_headers(https=False):
    """Extra headers for every response. The CSP is report-only unless CSP_ENFORCE=1 (the pages use inline scripts)."""
    h = [('X-Content-Type-Options', 'nosniff'),
         ('X-Frame-Options', 'DENY'),
         ('Referrer-Policy', 'strict-origin-when-cross-origin'),
         ('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(self "https://js.stripe.com")'),
         ('Content-Security-Policy' if os.environ.get('CSP_ENFORCE', '').strip() == '1'
          else 'Content-Security-Policy-Report-Only', _CSP)]
    if https and os.environ.get('HSTS', '').strip() == '1':
        h.append(('Strict-Transport-Security', 'max-age=31536000; includeSubDomains'))
    return h


# ---------------------------------------------------------------- rate limiting
_RL = _scout.POLICY.get('rate_limits') or {}
_HITS = defaultdict(deque)
_LOCK = threading.Lock()


def rate_limit_rule(path):
    if os.environ.get('RATE_LIMIT_ENABLED', '1').strip() == '0' or not _RL.get('enabled', True):
        return None
    rules = _RL.get('rules') or {}
    if path in rules:
        return path, rules[path]
    for prefix, rule in rules.items():            # a rule ending in "/" covers everything below it
        if prefix.endswith('/') and path.startswith(prefix):
            return prefix, rule
    return None


def rate_limited(path, ip, now=None):
    """Returns 0 if the request may go ahead, else the number of seconds to wait (for Retry-After)."""
    hit = rate_limit_rule(path)
    if not hit:
        return 0
    key, rule = hit
    now = now if now is not None else time.time()
    window = rule['window_seconds']
    with _LOCK:
        q = _HITS[(key, ip)]
        while q and now - q[0] >= window:
            q.popleft()
        if len(q) >= rule['count']:
            return max(1, int(window - (now - q[0])) + 1)
        q.append(now)
        if len(_HITS) > 20000:                    # keep memory bounded
            for k in [k for k, v in _HITS.items() if not v][:5000]:
                _HITS.pop(k, None)
    return 0


def reset_rate_limits():
    with _LOCK:
        _HITS.clear()


# ---------------------------------------------------------------- startup report
def startup_warnings():
    """Plain-language warnings printed at start-up so a risky setup is never silent."""
    w = []
    prod = is_production()
    try:
        from auth_engine import SMTP_CONFIGURED
    except Exception:
        SMTP_CONFIGURED = False
    if prod and not SMTP_CONFIGURED:
        w.append('SMTP is not configured: one-time codes cannot be emailed, so nobody can log in (codes are never shown on screen in production).')
    if prod and not _split('ALLOWED_ORIGINS'):
        w.append('ALLOWED_ORIGINS is not set: cross-origin browser calls are refused (fine if the site and API share one address).')
    if prod and not _split('TRUSTED_PROXIES'):
        w.append('TRUSTED_PROXIES is not set: if a load balancer sits in front, every customer will look like the same IP address.')
    if prod and os.environ.get('CSP_ENFORCE', '').strip() != '1':
        w.append('Content-Security-Policy is in report-only mode. Set CSP_ENFORCE=1 after checking the pages in a browser.')
    if prod and os.environ.get('HSTS', '').strip() != '1':
        w.append('HSTS is off. Set HSTS=1 once the site is served over HTTPS only.')
    if not (os.environ.get('ALERT_WEBHOOK_URL', '').strip() or os.environ.get('ALERT_EMAIL_TO', '').strip()):
        w.append('No alert destination: set ALERT_WEBHOOK_URL (Slack-style) and/or ALERT_EMAIL_TO to be told when an account is blocked.')
    return w


def show_dev_hints():
    """Development conveniences shown on screen: the login code in the page, the demo-account hint. Set SHOW_DEV_HINTS=0
    for a presentation or demo: the code then goes only to the person's email (or, without SMTP, to the server console)."""
    return os.environ.get('SHOW_DEV_HINTS', '1').strip().lower() not in ('0', 'false', 'no', 'off')
