#!/usr/bin/env python3
"""
TradeVerify AI — Scout Account Security & Fraud Screening Engine (Step B)
Real-time account security, authentication integrity, and billing fraud engine:
1. Multi-Factor Authentication (MFA) & Wrong OTP Lockout Risk Screening
2. Geolocation Anomaly & Unrecognized Device Fingerprint Detection (+ Haversine
   impossible-travel geo-velocity)
3. Credit Card Testing & Billing Carding Fraud Protection (back-to-back failures)
4. Rapid Automated Bilking / Bot-Speed Transaction Frequency Detection
5. Adaptive Risk-Based Step-Up MFA
6. Account Security Audit Orchestrator

STORAGE:
Velocity/session state is kept behind a pluggable store so this module works
correctly whether it's running as a single local process (PoC/dev) or behind
multiple workers/instances (production):
  - Set REDIS_URL (and have the `redis` package installed) to use Redis —
    state is then shared across every process/instance, which is required
    once you run more than one worker, since an attacker can otherwise dodge
    detection by hitting a different instance each time.
  - If REDIS_URL isn't set (or `redis` isn't installed), falls back to an
    in-memory store with a background sweep thread to bound memory growth.
    This fallback is fine for a single-process dev/demo run but does NOT
    share state across multiple processes/instances or survive a restart.
A one-time warning is logged at import time telling you which mode is active.
"""

import os
import json
import math as _math
import time as _time
import threading as _threading
import hashlib as _hashlib
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone

from fraud_policy import POLICY

_LOG = logging.getLogger("account_scout")

# --------------------------------------------------------------------------- #
# Fraud policy is externalized to fraud_policy.json. This keeps detection
# thresholds and risk weights out of application code so they can be tuned
# without changing the engine implementation.
# --------------------------------------------------------------------------- #

CARDING_POLICY = POLICY["carding"]
BOT_POLICY = POLICY["bot"]
RISK_POLICY = POLICY["risk_scoring"]
RISK_SIGNALS = RISK_POLICY["signals"]
RISK_CONDITIONS = RISK_POLICY["conditions"]
RISK_DECISIONS = RISK_POLICY["decisions"]
AUTH_POLICY = POLICY["authentication"]
BLOCK_DURATION_SEC = CARDING_POLICY["block_duration_seconds"]



# Max age any key is allowed to sit idle in the in-memory fallback store
# before the background sweep evicts it, so a long-running single-process
# deployment doesn't grow memory forever. Irrelevant when using Redis (TTLs
# there are set per-key instead).
_MEMORY_KEY_MAX_IDLE_SEC = POLICY['state']['memory_key_max_idle_seconds']
_MEMORY_SWEEP_INTERVAL_SEC = POLICY['state']['memory_sweep_interval_seconds']


# --------------------------------------------------------------------------- #
# Pluggable state store
# --------------------------------------------------------------------------- #

class _InMemoryStore:
    """
    Thread-safe sliding-window / key-value store for a single process.
    Bounded via a periodic background sweep that evicts anything idle longer
    than _MEMORY_KEY_MAX_IDLE_SEC, so memory doesn't grow unbounded in a
    long-running deployment. Does NOT share state across processes/instances
    — use Redis (set REDIS_URL) once you run more than one worker.
    """

    def __init__(self):
        self._lock = _threading.Lock()
        self._windows = defaultdict(deque)      # key -> deque[timestamps]
        self._dedup_windows = defaultdict(dict)  # key -> {value: last_seen_ts}
        self._kv = {}                            # key -> (value, touched_ts)
        self._blocked_until = {}                 # key -> unblock timestamp
        self._block_meta = {}                    # key -> details shown to the admin (type, reason, time...)
        self._touched = {}                        # key -> last-touched ts, for sweep
        t = _threading.Thread(target=self._sweep_loop, daemon=True)
        t.start()

    def _touch(self, key, now):
        self._touched[key] = now

    def _sweep_loop(self):
        while True:
            _time.sleep(_MEMORY_SWEEP_INTERVAL_SEC)
            self.sweep()

    def sweep(self):
        now = _time.time()
        cutoff = now - _MEMORY_KEY_MAX_IDLE_SEC
        with self._lock:
            stale = [k for k, ts in self._touched.items() if ts < cutoff]
            for k in stale:
                self._windows.pop(k, None)
                self._dedup_windows.pop(k, None)
                self._kv.pop(k, None)
                self._touched.pop(k, None)
            expired_blocks = [k for k, until in self._blocked_until.items() if until < now]
            for k in expired_blocks:
                self._blocked_until.pop(k, None)
                self._block_meta.pop(k, None)
        if stale or expired_blocks:
            _LOG.debug("account_scout in-memory sweep evicted %d idle keys, %d expired blocks",
                       len(stale), len(expired_blocks))

    def sliding_count(self, key: str, now: float, window_sec: float) -> int:
        with self._lock:
            dq = self._windows[key]
            dq.append(now)
            cutoff = now - window_sec
            while dq and dq[0] < cutoff:
                dq.popleft()
            self._touch(key, now)
            return len(dq)

    def peek_sliding_count(self, key: str, now: float, window_sec: float) -> int:
        with self._lock:
            dq = self._windows.get(key, deque())
            cutoff = now - window_sec
            return sum(1 for ts in dq if ts >= cutoff)

    def peek_sliding_distinct_count(self, key: str, now: float, window_sec: float) -> int:
        with self._lock:
            d = self._dedup_windows.get(key, {})
            cutoff = now - window_sec
            return sum(1 for ts in d.values() if ts >= cutoff)

    def sliding_distinct_count(self, key: str, now: float, value: str, window_sec: float) -> int:
        with self._lock:
            d = self._dedup_windows[key]
            d[value] = now
            cutoff = now - window_sec
            for v in [v for v, ts in d.items() if ts < cutoff]:
                del d[v]
            self._touch(key, now)
            return len(d)

    def get_last(self, key: str):
        with self._lock:
            entry = self._kv.get(key)
            return entry[0] if entry else None

    def set_last(self, key: str, now: float, value=None, ttl_sec=None):
        with self._lock:
            self._kv[key] = (value if value is not None else now, now)
            self._touch(key, now)

    def clear(self, key: str):
        with self._lock:
            self._windows.pop(key, None)
            self._kv.pop(key, None)
            self._touched.pop(key, None)

    def is_blocked(self, key: str, now: float) -> bool:
        with self._lock:
            until = self._blocked_until.get(key)
            return until is not None and now < until

    def block(self, key: str, now: float, duration_sec: float, meta: dict = None):
        with self._lock:
            self._blocked_until[key] = now + duration_sec
            self._block_meta[key] = dict(meta) if meta else {}
            self._touch(key, now)

    def get_block_meta(self, key: str) -> dict:
        with self._lock:
            return dict(self._block_meta.get(key) or {})

    def list_blocked(self, now: float) -> list:
        """Admin panel support: every key currently blocked, with seconds remaining and why."""
        with self._lock:
            return [{'key': k, 'seconds_remaining': round(until - now, 1), 'meta': dict(self._block_meta.get(k) or {})}
                    for k, until in self._blocked_until.items() if until > now]

    def unblock(self, key: str) -> bool:
        """Admin panel support: manually clear a block. Returns True if one existed."""
        with self._lock:
            self._block_meta.pop(key, None)
            return self._blocked_until.pop(key, None) is not None


class _RedisStore:
    """
    Redis-backed store — required once this runs behind more than one
    process/worker/instance, so all of them see the same velocity state and
    an attacker can't dodge detection by hitting a different instance.
    Sliding windows use ZSETs (ZADD/ZREMRANGEBYSCORE/ZCARD) with a TTL so
    Redis itself reclaims memory for keys that go idle — no separate sweep
    needed.
    """

    def __init__(self, client, prefix="scout:"):
        self._r = client
        self._p = prefix

    def _k(self, key):
        return f"{self._p}{key}"

    def sliding_count(self, key: str, now: float, window_sec: float) -> int:
        k = self._k(f"win:{key}")
        pipe = self._r.pipeline()
        pipe.zadd(k, {f"{now}:{os.urandom(4).hex()}": now})
        pipe.zremrangebyscore(k, 0, now - window_sec)
        pipe.zcard(k)
        pipe.expire(k, int(window_sec) + 60)
        _, _, count, _ = pipe.execute()
        return int(count)

    def sliding_distinct_count(self, key: str, now: float, value: str, window_sec: float) -> int:
        k = self._k(f"dedup:{key}")
        pipe = self._r.pipeline()
        pipe.zadd(k, {value: now})
        pipe.zremrangebyscore(k, 0, now - window_sec)
        pipe.zcard(k)
        pipe.expire(k, int(window_sec) + 60)
        _, _, count, _ = pipe.execute()
        return int(count)

    def peek_sliding_count(self, key: str, now: float, window_sec: float) -> int:
        k = self._k(f"win:{key}")
        self._r.zremrangebyscore(k, 0, now - window_sec)
        return int(self._r.zcard(k))

    def peek_sliding_distinct_count(self, key: str, now: float, window_sec: float) -> int:
        k = self._k(f"dedup:{key}")
        self._r.zremrangebyscore(k, 0, now - window_sec)
        return int(self._r.zcard(k))

    def get_last(self, key: str):
        raw = self._r.get(self._k(f"kv:{key}"))
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    def set_last(self, key: str, now: float, value=None, ttl_sec: int = 7 * 24 * 3600):
        self._r.set(self._k(f"kv:{key}"), json.dumps(value if value is not None else now), ex=ttl_sec)

    def clear(self, key: str):
        self._r.delete(self._k(f"kv:{key}"), self._k(f"win:{key}"))

    def is_blocked(self, key: str, now: float) -> bool:
        return self._r.exists(self._k(f"blk:{key}")) == 1

    def block(self, key: str, now: float, duration_sec: float, meta: dict = None):
        import json as _json
        self._r.set(self._k(f"blk:{key}"), _json.dumps(meta) if meta else "1", ex=int(duration_sec))

    def get_block_meta(self, key: str) -> dict:
        import json as _json
        try:
            raw = self._r.get(self._k(f"blk:{key}"))
            data = _json.loads(raw) if raw and raw != "1" else {}
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def list_blocked(self, now: float) -> list:
        """Admin panel support: every key currently blocked, with seconds remaining."""
        results = []
        prefix = self._k("blk:")
        for redis_key in self._r.scan_iter(match=f"{prefix}*"):
            ttl = self._r.ttl(redis_key)
            if ttl and ttl > 0:
                results.append({'key': redis_key[len(prefix):], 'seconds_remaining': ttl,
                                'meta': self.get_block_meta(redis_key[len(prefix):])})
        return results

    def unblock(self, key: str) -> bool:
        """Admin panel support: manually clear a block. Returns True if one existed."""
        return self._r.delete(self._k(f"blk:{key}")) > 0


def _init_store():
    redis_url = os.environ.get('REDIS_URL')
    storage_mode = os.environ.get('SCOUT_STORAGE_MODE', 'auto').strip().lower()
    if storage_mode not in ('auto', 'redis', 'memory'):
        raise RuntimeError("SCOUT_STORAGE_MODE must be one of: auto, redis, memory")
    if storage_mode == 'redis' and not redis_url:
        raise RuntimeError("SCOUT_STORAGE_MODE=redis requires REDIS_URL")
    if redis_url and storage_mode != 'memory':
        try:
            import redis  # type: ignore
            client = redis.Redis.from_url(redis_url, decode_responses=True, socket_timeout=2)
            client.ping()
            _LOG.warning("account_scout: using REDIS-backed store — state is shared across instances.")
            return _RedisStore(client)
        except Exception as e:
            if storage_mode == 'redis':
                raise RuntimeError(f"Redis is required but unavailable: {e}") from e
            _LOG.warning("account_scout: REDIS_URL set but Redis unavailable (%s) — using in-memory store for local/demo mode.", e)
    if storage_mode == 'redis':
        raise RuntimeError("Redis storage was requested but could not be initialized")
    _LOG.warning("account_scout: using in-memory store. Use SCOUT_STORAGE_MODE=redis with REDIS_URL for multi-instance production.")
    return _InMemoryStore()


_STORE = _init_store()


def get_payment_idempotency(account_id: str, idempotency_key: str):
    if not account_id or not idempotency_key:
        return None
    return _STORE.get_last(f"idem:{account_id}:{idempotency_key}")


def save_payment_idempotency(account_id: str, idempotency_key: str, result: dict):
    if account_id and idempotency_key:
        _STORE.set_last(f"idem:{account_id}:{idempotency_key}", _time.time(), result, ttl_sec=POLICY["state"]["idempotency_ttl_seconds"])



def reset_live_state():
    """Clears all live velocity state. Intended for tests / demo resets only."""
    global _STORE
    _STORE = _init_store() if not isinstance(_STORE, _InMemoryStore) else _InMemoryStore()


def _session_block_applies(key: str, account_id: str, now: float) -> bool:
    """
    A block on a browser checkout session belongs to the account that caused it. A DIFFERENT account that happens
    to use the same browser tab is not punished for it (account and card blocks still apply to everyone they name).
    """
    if not is_blocked(key, now):
        return False
    if not key.startswith('session:') or not account_id:
        return True
    owner = _STORE.get_block_meta(key).get('account_id') or ''
    return (not owner) or owner == account_id


def is_blocked(key: str, now: float = None) -> bool:
    now = now if now is not None else _time.time()
    return _STORE.is_blocked(key, now)


def list_blocked(now: float = None) -> list:
    """Admin panel support: lists every currently-active block (card, session,
    or account) with how many seconds remain, sorted soonest-to-expire last."""
    now = now if now is not None else _time.time()
    results = _STORE.list_blocked(now)
    return sorted(results, key=lambda r: -r['seconds_remaining'])


def unblock(key: str) -> bool:
    """Admin panel support: manually clears one block by its exact key
    (e.g. 'account:exporter:Demo', 'card:demo_attack_card_fixed',
    'session:checkout-123'). Returns True if a block existed and was cleared.

    A bot detection freezes BOTH the session and the account. Unblocking either
    one clears the whole incident and resets the session's speed counters, so a
    genuine customer restored by the admin starts from a clean slate."""
    meta = _STORE.get_block_meta(key)
    cleared = _STORE.unblock(key)
    for related_key in meta.get('related', []) or []:
        if _STORE.unblock(related_key):
            cleared = True
    session_id = meta.get('session_id')
    if meta.get('type') == 'bot' and session_id:
        _acct = meta.get('account_id') or ''
        for counter in (f'botstrike:{session_id}', f'botattempt:{session_id}',
                        f'lastseen:{session_id}', f'lastip:{session_id}',
                        f'rate:{_acct}' if _acct else '', f'rate:session:{session_id}',
                        f'botstrike:{_acct}' if _acct else '', f'botstrike:session:{session_id}'):
            if counter:
                _STORE.clear(counter)
    try:
        from bot_signals import reset_account
        reset_account(meta.get('account_id') or '')
    except Exception:
        pass
    return cleared


# ---- Block reference IDs + escalating locks (policy section "escalation") ----
ESC_POLICY = POLICY.get("escalation") or {}
_ESC_LOCK = _threading.Lock()
_INCIDENTS = []       # recent incidents for the admin stats card: {'at','account','level','ref','kind'} (in memory)
_BLOCK_HISTORY = {}   # account_id -> {'times': [...], 'level': int, 'ref': str, 'at': float}  (in-memory, per process)


def _make_reference(seed: str) -> str:
    """Short, support-friendly case number, e.g. TV-83F2A1."""
    return 'TV-' + _hashlib.sha1(seed.encode('utf-8')).hexdigest()[:6].upper()


def _incident_for(account_id: str, key: str, now: float):
    """
    One fraud incident can block several keys (session, account, card) in the same moment; they all share one
    reference ID and one lock level. Returns (level, reference, lock_seconds, needs_review).
    Level 1 = first lock in the history window (the normal block_duration_seconds); repeat locks get longer.
    """
    if not account_id:
        return 1, _make_reference(f'{key}|{now}'), BLOCK_DURATION_SEC, False
    window = ESC_POLICY.get('history_window_seconds', 86400)
    with _ESC_LOCK:
        h = _BLOCK_HISTORY.setdefault(account_id, {'times': [], 'level': 1, 'ref': '', 'at': 0.0})
        h['times'] = [t for t in h['times'] if now - t < window]
        same_incident = bool(h['ref']) and (now - h['at'] < 0.25 or _STORE.is_blocked(f'account:{account_id}', now))
        if not same_incident:
            h['times'].append(now)
            h['at'] = now
            h['level'] = len(h['times'])
            h['ref'] = _make_reference(f'{account_id}|{now}')
            _INCIDENTS.append({'at': now, 'account': account_id, 'level': h['level'], 'ref': h['ref'], 'kind': ''})
            del _INCIDENTS[:-500]
        level, ref = h['level'], h['ref']
    if not ESC_POLICY.get('enabled', True):
        return 1, ref, BLOCK_DURATION_SEC, False
    repeats = ESC_POLICY.get('repeat_lock_durations_seconds') or []
    duration = BLOCK_DURATION_SEC if level <= 1 or not repeats else max(BLOCK_DURATION_SEC, repeats[min(level - 2, len(repeats) - 1)])
    return level, ref, duration, level >= ESC_POLICY.get('manual_review_level', 3)


def _lock_seconds(account_id: str) -> float:
    """How long the account's current lock really is (escalated), for the 'try again in N min' messages."""
    if account_id:
        meta = _STORE.get_block_meta(f'account:{account_id}')
        if meta.get('lock_seconds'):
            return meta['lock_seconds']
    return BLOCK_DURATION_SEC


def _block_key(key: str, now: float, kind: str, reason: str, account_id: str = '', **extra):
    """Block one key and remember WHY, so the admin page can explain it."""
    meta = {'type': kind, 'reason': reason, 'blocked_at': now, 'account_id': account_id or ''}
    meta.update(extra)
    _level, _ref, _duration, _review = _incident_for(account_id, key, now)
    meta.update({'reference': _ref, 'lock_level': _level, 'lock_seconds': _duration, 'needs_review': _review})
    for _inc in reversed(_INCIDENTS[-5:]):
        if _inc['ref'] == _ref and not _inc['kind']:
            _inc['kind'] = kind
            break
    _STORE.block(key, now, _duration, meta)
    try:
        from alerts import notify_block
        notify_block(key, meta, now)          # one background alert per incident; can never fail or delay a payment
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Problem 3 — Back-to-Back Credit Card Failures (card testing / carding sweeps)
# --------------------------------------------------------------------------- #

def _risk_decision(score: float) -> str:
    """Bands come straight from fraud_policy.json (risk_scoring.decisions):
        score <  allow_below            -> ALLOW
        score <  step_up_below          -> STEP_UP_REQUIRED
        score <  review_below           -> REVIEW
        score >= block_at_or_above      -> BLOCK
    (Previously REVIEW was unreachable and ALLOW covered everything below 60.)"""
    if score >= RISK_DECISIONS["block_at_or_above"]:
        return "BLOCK"
    if score >= RISK_DECISIONS["step_up_below"]:
        return "REVIEW"
    if score >= RISK_DECISIONS["allow_below"]:
        return "STEP_UP_REQUIRED"
    return "ALLOW"


def evaluate_payment_risk(carding_result: dict, bot_result: dict,
                          account_id: str = '', ip: str = '',
                          previous_fraud_block: bool = False) -> dict:
    """Combine independent payment signals into one configurable decision."""
    score = 0
    reasons = []

    if carding_result.get('success') is False:
        score += RISK_SIGNALS["payment_failure"]
        reasons.append("payment authorization failed")
    failed = int(carding_result.get('failed_attempts') or 0)
    if failed >= RISK_CONDITIONS["repeated_failure_count"]:
        score += RISK_SIGNALS["two_failures_in_window"]
        reasons.append("repeated payment failures")
    if carding_result.get('same_card_threshold_reached'):
        score += RISK_SIGNALS["same_payment_method_failure_threshold"]
        reasons.append("same payment method failure threshold reached")
    if carding_result.get('account_failure_threshold_reached'):
        score += RISK_SIGNALS["account_failure_threshold"]
        reasons.append("too many failed payments on this account")
    if carding_result.get('distinct_card_threshold_reached'):
        score += RISK_SIGNALS["distinct_payment_methods_threshold"]
        reasons.append("multiple payment methods used in a short window")
    if carding_result.get('failed_attempt_burst'):
        score += RISK_SIGNALS["failed_attempt_burst"]
        reasons.append("failed-attempt burst detected")
    if bot_result.get('fast_gap'):
        score += RISK_SIGNALS["fast_payment_gap"]
        reasons.append("payment requests arriving too quickly")
    if bot_result.get('strike_threshold_reached'):
        score += RISK_SIGNALS["bot_strike_threshold"]
        reasons.append("repeated rapid-payment strikes")
    if bot_result.get('new_ip'):
        score += RISK_SIGNALS["new_ip"]
        reasons.append("new network address for this account/session")
    if previous_fraud_block:
        score += RISK_SIGNALS["active_fraud_block"]
        reasons.append("active fraud block already exists")

    decision = _risk_decision(score)
    return {
        'score': score,
        'decision': decision,
        'reasons': reasons,
        'policy_version': POLICY.get('version'),
        'details': f"Payment risk score {score}: {decision}." + (" " + "; ".join(reasons) if reasons else " No elevated payment signals.")
    }


def record_card_authorization(session_id: str, card_fingerprint: str, success: bool = None,
                               ip: str = '', bin_prefix: str = '', account_id: str = '',
                               timestamp: float = None, register_attempt: bool = True) -> dict:
    """Record one payment attempt/outcome and evaluate card-testing signals.

    success=None means the provider outcome is not known yet (pre-authorization).
    In that phase we still count the attempt/payment method for velocity signals,
    but we do not count it as a success or failure. The authoritative True/False
    outcome is recorded later from the payment provider result/webhook.
    """
    now = timestamp if timestamp is not None else _time.time()
    session_id = session_id or 'unknown_session'
    card_fingerprint = card_fingerprint or 'unknown_payment_method'
    ip = ip or 'unknown_ip'

    reasons = []
    card_fail_count = 0
    blocked_keys = [f'card:{card_fingerprint}', f'session:{session_id}']
    if account_id:
        blocked_keys.append(f'account:{account_id}')
    _hit_keys = [k for k in blocked_keys if _session_block_applies(k, account_id, now)]
    if _hit_keys:
        _types = {(_STORE.get_block_meta(k).get('type') or 'carding') for k in _hit_keys}
        return {
            'carding_detected': True, 'status': 'CARDING_RED_FLAG',
            'block_type': 'bot' if 'bot' in _types else 'carding',
            'failed_attempts': None, 'distinct_cards_in_session': None,
            'success': success, 'active_block': True,
            'attempts_remaining': 0, 'retry_after_seconds': _lock_seconds(account_id),
            'details': f"CARDING RED FLAG: payment session or account is under an active fraud block."
        }

    attempts_window = CARDING_POLICY["attempt_burst_with_failures"]["window_seconds"]
    distinct_window = CARDING_POLICY["distinct_payment_methods"]["window_seconds"]

    # Pre-authorization: register this customer payment attempt exactly once.
    # Provider outcome is still unknown at this point.
    if register_attempt:
        attempt_burst = _STORE.sliding_count(f'attempts:session:{session_id}', now, attempts_window)
        distinct_cards = _STORE.sliding_distinct_count(f'cards_seen:{session_id}', now, card_fingerprint, distinct_window)
        distinct_cards_ip = _STORE.sliding_distinct_count(f'cards_seen_ip:{ip}', now, card_fingerprint, distinct_window)
        distinct_cards_account = None
        if account_id:
            distinct_cards_account = _STORE.sliding_distinct_count(f'cards_seen_account:{account_id}', now, card_fingerprint, distinct_window)
            _STORE.sliding_count(f'attempts:account:{account_id}', now, attempts_window)
        ip_attempts = _STORE.sliding_count(f'attempts:ip:{ip}', now, attempts_window)
    else:
        # Provider callback/webhook: never count a second customer attempt.
        attempt_burst = _STORE.peek_sliding_count(f'attempts:session:{session_id}', now, attempts_window)
        distinct_cards = _STORE.peek_sliding_distinct_count(f'cards_seen:{session_id}', now, distinct_window)
        distinct_cards_ip = _STORE.peek_sliding_distinct_count(f'cards_seen_ip:{ip}', now, distinct_window)
        distinct_cards_account = (_STORE.peek_sliding_distinct_count(f'cards_seen_account:{account_id}', now, distinct_window) if account_id else None)
        ip_attempts = _STORE.peek_sliding_count(f'attempts:ip:{ip}', now, attempts_window)

    # Existing failure state is read without manufacturing a failure.
    card_fail_count = _STORE.peek_sliding_count(
        f'card_fail:{card_fingerprint}', now,
        CARDING_POLICY["same_payment_method_failures"]["window_seconds"])
    failed_burst = _STORE.peek_sliding_count(f'failed:session:{session_id}', now, attempts_window)

    account_fail_count = 0
    account_fail_cfg = CARDING_POLICY["account_failures"]
    if success is True:
        # Genuine-customer recovery: a payment that goes through ends the failure streak.
        # Earlier failures on this card (typos, expired-card retries) and on the account are wiped,
        # so only failures BACK TO BACK (with no successful payment in between) can add up to a block.
        _STORE.clear(f'card_fail:{card_fingerprint}')
        if account_id:
            _STORE.clear(f'failed:account:{account_id}')
        card_fail_count = 0
    elif success is None and account_id:
        account_fail_count = _STORE.peek_sliding_count(f'failed:account:{account_id}', now, account_fail_cfg["window_seconds"])

    if success is False:
        # Only the actual provider failure creates failure events.
        if account_id:
            # Back-to-back failures on the ACCOUNT across ANY card or session
            # (a thief trying stolen cards, or a bot rotating cards and sessions).
            account_fail_count = _STORE.sliding_count(f'failed:account:{account_id}', now, account_fail_cfg["window_seconds"])
            if account_fail_count >= account_fail_cfg["count"]:
                _why = (f"{account_fail_count} failed payments in a row on this account "
                        f"(within {account_fail_cfg['window_seconds']}s): stolen-card testing suspected")
                _block_key(f'session:{session_id}', now, 'carding', _why, account_id)
                _block_key(f'account:{account_id}', now, 'carding', _why, account_id)
                reasons.append(_why)
        _STORE.sliding_count(f'failed:session:{session_id}', now, attempts_window)
        _STORE.sliding_count(
            f'card_fail:{card_fingerprint}', now,
            CARDING_POLICY["same_payment_method_failures"]["window_seconds"])
        failed_burst = _STORE.peek_sliding_count(f'failed:session:{session_id}', now, attempts_window)
        card_fail_count = _STORE.peek_sliding_count(
            f'card_fail:{card_fingerprint}', now,
            CARDING_POLICY["same_payment_method_failures"]["window_seconds"])
        if card_fail_count >= CARDING_POLICY["same_payment_method_failures"]["count"]:
            _block_key(f'card:{card_fingerprint}', now, 'carding', 'Back-to-back failed card payments (stolen-card testing suspected)', account_id)
            if account_id:
                _block_key(f'account:{account_id}', now, 'carding', 'Back-to-back failed card payments (stolen-card testing suspected)', account_id)
            reasons.append(
                f"{card_fail_count} failures on the same payment method within "
                f"{CARDING_POLICY['same_payment_method_failures']['window_seconds']}s")

    same_threshold = (card_fail_count >= CARDING_POLICY["same_payment_method_failures"]["count"])
    distinct_threshold = ((distinct_cards >= CARDING_POLICY["distinct_payment_methods"]["count"] or distinct_cards_ip >= CARDING_POLICY["distinct_payment_methods"]["count"] or (distinct_cards_account is not None and distinct_cards_account >= CARDING_POLICY["distinct_payment_methods"]["count"])) and failed_burst >= CARDING_POLICY["distinct_payment_methods"]["minimum_failures_for_block"])
    failed_burst_threshold = (
        failed_burst >= CARDING_POLICY["attempt_burst_with_failures"]["count"] and
        attempt_burst >= CARDING_POLICY["attempt_burst_with_failures"]["count"]
    )
    if distinct_threshold:
        _block_key(f'session:{session_id}', now, 'carding', 'Back-to-back failed card payments (stolen-card testing suspected)', account_id)
        if account_id:
            _block_key(f'account:{account_id}', now, 'carding', 'Back-to-back failed card payments (stolen-card testing suspected)', account_id)
        reasons.append(
            f"{distinct_cards} distinct payment methods within "
            f"{CARDING_POLICY['distinct_payment_methods']['window_seconds']}s")
    if failed_burst_threshold:
        _block_key(f'session:{session_id}', now, 'carding', 'Back-to-back failed card payments (stolen-card testing suspected)', account_id)
        if account_id:
            _block_key(f'account:{account_id}', now, 'carding', 'Back-to-back failed card payments (stolen-card testing suspected)', account_id)
        reasons.append(
            f"{failed_burst} failed attempts within {attempts_window}s")

    detected = bool(reasons)
    if detected:
        details = f"CARDING RED FLAG: Active payment card-testing pattern detected! {'; '.join(reasons)}. Payment session suspended."
        try:
            from alert_engine import send_block_alert
            send_block_alert('carding', f'session:{session_id}', details, account_id=account_id)
        except Exception as e:
            _LOG.error("account_scout: alert dispatch failed (non-fatal): %s", e)
    else:
        details = f"Billing session clear ({card_fail_count} failed authorization attempts, {distinct_cards} payment method(s))."

    return {
        'carding_detected': detected,
        'status': 'CARDING_RED_FLAG' if detected else 'PASSED',
        'failed_attempts': card_fail_count,
        'distinct_cards_in_session': distinct_cards,
        'distinct_cards_from_ip': distinct_cards_ip,
        'distinct_cards_for_account': distinct_cards_account,
        'attempts_in_window': attempt_burst,
        'failed_attempts_in_burst': failed_burst,
        'block_type': 'carding' if detected else None,
        'attempts_remaining': 0 if detected else max(0, min(
            CARDING_POLICY["same_payment_method_failures"]["count"] - card_fail_count,
            (account_fail_cfg["count"] - account_fail_count) if account_id else 10**6)),
        'retry_after_seconds': _lock_seconds(account_id) if detected else None,
        'account_failures_in_window': account_fail_count,
        'account_failure_threshold_reached': account_fail_count >= account_fail_cfg["count"],
        'same_card_threshold_reached': same_threshold,
        'distinct_card_threshold_reached': distinct_threshold,
        'failed_attempt_burst': failed_burst_threshold,
        'ip_attempts_in_window': ip_attempts,
        'success': success,
        'active_block': detected,
        'details': details
    }


def account_security_status(account_id: str, now: float = None) -> dict:
    """Live, automatic status of one account for the header badge: protected / warning / blocked."""
    now = now if now is not None else _time.time()
    risk = get_account_risk(account_id, now=now)
    if risk.get('status') == 'CARDING_RED_FLAG':
        kind = risk.get('block_type') or 'carding'
        mins = max(1, round(BLOCK_DURATION_SEC / 60))
        return {'state': 'blocked', 'kind': kind,
                'label': 'Blocked: bot activity' if kind == 'bot' else 'Blocked: card testing',
                'details': f"Payments are paused. An administrator can unblock it, or it clears by itself (up to {mins} min)."}
    strikes = _STORE.peek_sliding_count(f'botstrike:{account_id}', now, BOT_POLICY['strike_window_seconds'])
    if strikes > 0:
        return {'state': 'warning', 'kind': 'bot', 'label': 'Warning: payments too fast',
                'details': 'Payments arrived faster than a person normally pays. A repeat will block the account.'}
    fails = _STORE.peek_sliding_count(f'failed:account:{account_id}', now, CARDING_POLICY['account_failures']['window_seconds'])
    if fails > 0:
        return {'state': 'warning', 'kind': 'carding', 'label': f"Warning: {fails} failed payment{'s' if fails != 1 else ''}",
                'details': 'Repeated failed card payments will block the account.'}
    return {'state': 'clean', 'kind': '', 'label': 'Protected: no threats', 'details': 'No suspicious payment activity on this account.'}


def get_account_risk(account_id: str, now: float = None) -> dict:
    """
    Looks up whether this account currently has an active carding/bot block
    against it (set by record_card_authorization / record_transaction_event
    when account_id was supplied during checkout). This is what lets a login
    attempt know "this account had a carding attack a few minutes ago" even
    though login and checkout use completely different session_ids.
    """
    now = now if now is not None else _time.time()
    if not account_id or not is_blocked(f'account:{account_id}', now):
        return {'carding_detected': False, 'status': 'PASSED',
                'details': 'No active fraud block on this account.'}
    return {
        'carding_detected': True,
        'status': 'CARDING_RED_FLAG',
        'block_type': _STORE.get_block_meta(f'account:{account_id}').get('type') or 'carding',
        'details': f"CARDING RED FLAG: account '{account_id}' has an active fraud block from a recent "
                    f"card-testing/bot detection on this account's checkout activity."
    }


# --------------------------------------------------------------------------- #
# Problem 4 — Carding & Rapid Automated Bilking (bot-speed detection)
# --------------------------------------------------------------------------- #

SLOW_DOWN_MESSAGE = ("Please slow down: payments are being submitted faster than a person normally pays. "
                     "Wait a few seconds and try again. If it happens again, this account will be blocked.")
SLOW_DOWN_SECONDS = 5


def _slow_down(gap_ms, strikes, burst, rate_count, rate_window, why):
    """First offence: refuse THIS attempt with a 'slow down' warning. A repeat within the strike window blocks."""
    return {
        'bot_detected': False, 'status': 'SUSPECT', 'gap_ms': gap_ms, 'strikes': strikes,
        'attempt_burst': burst, 'rate_count': rate_count, 'rate_window_seconds': rate_window,
        'fast_gap': True, 'strike_threshold_reached': False, 'active_block': False, 'new_ip': False,
        'slow_down': True, 'retry_after_seconds': SLOW_DOWN_SECONDS, 'alert': SLOW_DOWN_MESSAGE,
        'details': f"WARNING: {why}. Slow down; a repeat within {BOT_POLICY['strike_window_seconds']}s blocks the account "
                   f"(strike {strikes}/{BOT_POLICY['strike_count']})."
    }


BOT_ALERT_MESSAGE = ("Account may be under attack by a bot: payments are being submitted faster than a human can. "
                     "This account has been blocked for security.")


def _flag_bot(session_id, account_id, ip, now, bot_details, gap_ms, extra):
    """Block the session AND the account for automated payment speed, tell the admin, return the result."""
    session_key = f'session:{session_id}'
    account_key = f'account:{account_id}' if account_id else ''
    _block_key(session_key, now, 'bot', bot_details, account_id, session_id=session_id, ip=ip,
               gap_ms=gap_ms, related=[account_key] if account_key else [])
    if account_key:
        _block_key(account_key, now, 'bot', bot_details, account_id, session_id=session_id, ip=ip,
                   gap_ms=gap_ms, related=[session_key])
    try:
        from alert_engine import send_block_alert
        send_block_alert('bot', account_key or session_key, bot_details, account_id=account_id)
    except Exception as e:
        _LOG.error("account_scout: alert dispatch failed (non-fatal): %s", e)
    result = {
        'bot_detected': True, 'status': 'BOT_RED_FLAG', 'gap_ms': gap_ms,
        'fast_gap': True, 'active_block': True, 'block_type': 'bot',
        'alert': BOT_ALERT_MESSAGE, 'retry_after_seconds': BLOCK_DURATION_SEC,
        'details': f"BOT RED FLAG: {bot_details}"
    }
    result.update(extra)
    return result


def record_transaction_event(session_id: str, timestamp: float = None, account_id: str = '', ip: str = '') -> dict:
    """Track payment timing. A payment that arrives sooner after the previous one than a
    person plausibly could is a bot signal; at `bot.strike_count` such signals the session AND
    the account are blocked immediately and the admin can see and unblock them."""
    now = timestamp if timestamp is not None else _time.time()
    session_id = session_id or 'unknown_session'
    ip = ip or 'unknown_ip'

    _frozen = [k for k in (f'session:{session_id}', f'account:{account_id}' if account_id else '') if k and _session_block_applies(k, account_id, now)]
    if _frozen:
        if any(_STORE.get_block_meta(k).get('type') == 'bot' for k in _frozen):
            return {
                'bot_detected': True, 'status': 'BOT_RED_FLAG', 'gap_ms': None,
                'strike_threshold_reached': True, 'fast_gap': True, 'active_block': True,
                'block_type': 'bot', 'alert': BOT_ALERT_MESSAGE, 'retry_after_seconds': BLOCK_DURATION_SEC,
                'details': "BOT RED FLAG: this account/session is blocked for automated payment activity."
            }
        # Frozen by the card-testing rule, not by speed: nothing to add from the bot check.
        return {'bot_detected': False, 'status': 'PASSED', 'gap_ms': None, 'strikes': 0,
                'fast_gap': False, 'strike_threshold_reached': False, 'active_block': True,
                'details': 'Session already frozen by the card-testing rule.'}

    last_ts = _STORE.get_last(f'lastseen:{session_id}')
    last_ip = _STORE.get_last(f'lastip:{session_id}')
    _STORE.set_last(f'lastseen:{session_id}', now)
    _STORE.set_last(f'lastip:{session_id}', now, ip)

    burst = _STORE.sliding_count(
        f'botattempt:{session_id}', now,
        BOT_POLICY["attempt_burst_window_seconds"])
    # Speed rule 2 (rate): too many payments inside a short window, even if each gap looks human.
    # Counted per ACCOUNT (a bot cannot dodge it by changing session ids); per session when no account is known.
    rate_key = f'rate:{account_id}' if account_id else f'rate:session:{session_id}'
    strike_key = f'botstrike:{account_id}' if account_id else f'botstrike:session:{session_id}'
    rate_window = BOT_POLICY["rate_limit_window_seconds"]
    rate_count = _STORE.sliding_count(rate_key, now, rate_window)
    if rate_count >= BOT_POLICY["rate_limit_count"]:
        gap_now = None if last_ts is None else round((now - float(last_ts)) * 1000, 1)
        rate_strikes = _STORE.sliding_count(strike_key, now, BOT_POLICY["strike_window_seconds"])
        if rate_strikes >= BOT_POLICY["strike_count"]:
            return _flag_bot(
                session_id, account_id, ip, now,
                f"{rate_count} payments within {rate_window} seconds, repeated after a warning (a person cannot pay this fast). Account and session blocked.",
                gap_now, {'strikes': rate_strikes, 'attempt_burst': burst, 'rate_count': rate_count, 'rate_window_seconds': rate_window,
                          'strike_threshold_reached': True, 'rate_threshold_reached': True, 'new_ip': False})
        return _slow_down(gap_now, rate_strikes, burst, rate_count, rate_window, f"{rate_count} payments within {rate_window} seconds")

    if last_ts is None:
        return {'bot_detected': False, 'status': 'PASSED', 'gap_ms': None, 'strikes': 0,
                'fast_gap': False, 'strike_threshold_reached': False,
                'attempt_burst': burst, 'rate_count': rate_count, 'rate_window_seconds': rate_window, 'new_ip': False,
                'details': 'First payment transaction observed for this session.'}

    gap_ms = (now - float(last_ts)) * 1000
    fast_gap = gap_ms < BOT_POLICY["minimum_human_gap_ms"]
    new_ip = bool(last_ip and last_ip != ip)
    if not fast_gap:
        return {'bot_detected': False, 'status': 'PASSED', 'gap_ms': round(gap_ms, 1), 'strikes': 0,
                'fast_gap': False, 'strike_threshold_reached': False,
                'attempt_burst': burst, 'rate_count': rate_count, 'rate_window_seconds': rate_window, 'new_ip': new_ip,
                'details': f"Inter-transaction gap {gap_ms:.0f}ms is within the configured human-plausible range."}

    strikes = _STORE.sliding_count(strike_key, now, BOT_POLICY["strike_window_seconds"])
    strike_threshold = strikes >= BOT_POLICY["strike_count"]
    burst_threshold = burst >= BOT_POLICY["attempt_burst_count"]
    if strike_threshold or burst_threshold:
        reasons = []
        if strike_threshold:
            reasons.append(f"payment sent {gap_ms:.0f} ms after the previous one (a person needs {BOT_POLICY['minimum_human_gap_ms']} ms or more)")
        if burst_threshold:
            reasons.append(f"{burst} payment attempts within {BOT_POLICY['attempt_burst_window_seconds']}s")
        bot_details = f"{' and '.join(reasons)} (automated payment speed). Account and session blocked."
        return _flag_bot(
            session_id, account_id, ip, now, bot_details, round(gap_ms, 1),
            {'strikes': strikes, 'attempt_burst': burst, 'rate_count': rate_count, 'rate_window_seconds': rate_window,
             'strike_threshold_reached': strike_threshold, 'new_ip': new_ip})

    return _slow_down(round(gap_ms, 1), strikes, burst, rate_count, rate_window,
                      f"payment sent {gap_ms:.0f} ms after the previous one (a person needs {BOT_POLICY['minimum_human_gap_ms']} ms or more)")


def record_slow_bot_signal(session_id: str, account_id: str, ip: str, why: str, now: float = None) -> dict:
    """
    A bot signal that is NOT raw speed (form filled too quickly, machine-regular rhythm). It uses the same
    strike counter as the speed rule: the first one is a warning, a repeat within the strike window blocks.
    """
    now = now if now is not None else _time.time()
    session_id = session_id or 'unknown_session'
    ip = ip or 'unknown_ip'
    strike_key = f'botstrike:{account_id}' if account_id else f'botstrike:session:{session_id}'
    strikes = _STORE.sliding_count(strike_key, now, BOT_POLICY["strike_window_seconds"])
    if strikes >= BOT_POLICY["strike_count"]:
        return _flag_bot(session_id, account_id, ip, now,
                         f"{why} (automated payment behaviour, repeated after a warning). Account and session blocked.",
                         None, {'strikes': strikes, 'strike_threshold_reached': True, 'new_ip': False})
    res = _slow_down(None, strikes, 0, 0, BOT_POLICY["rate_limit_window_seconds"], why)
    res['alert'] = ("Please slow down: this payment looks automated (" + why + "). Wait a few seconds and try again. "
                    "If it happens again, this account will be blocked.")
    return res


# --------------------------------------------------------------------------- #
# Problem 5 — Adaptive Risk-Based Step-Up MFA
# --------------------------------------------------------------------------- #

def record_otp_attempt(session_id: str, success: bool, timestamp: float = None) -> dict:
    """
    Real, stateful OTP failure tracking, replacing the old approach where the
    caller had to pass in its own failed-attempt count. A successful OTP
    clears the session's failure streak.
    """
    now = timestamp if timestamp is not None else _time.time()
    session_id = session_id or 'unknown_session'

    if success:
        _STORE.clear(f'otp_fail:{session_id}')
        return {'status': 'PASSED', 'failed_attempts': 0,
                'details': 'OTP verified successfully; failure streak cleared.'}

    count = _STORE.sliding_count(f'otp_fail:{session_id}', now, AUTH_POLICY["otp_failure_window_seconds"])
    if count >= AUTH_POLICY["otp_alert_threshold"]:
        return {'status': 'ALERT', 'failed_attempts': count,
                'details': f"ALERT: {count} consecutive wrong OTP submissions within "
                            f"{AUTH_POLICY["otp_failure_window_seconds"]}s (possible credential stuffing)."}
    return {'status': 'WARN' if count > 0 else 'PASSED', 'failed_attempts': count,
            'details': f"OTP status: {count}/{AUTH_POLICY["otp_alert_threshold"]} failed attempts in current window."}


def evaluate_adaptive_step_up(otp_result: dict = None, geo_result: dict = None,
                               carding_result: dict = None, bot_result: dict = None) -> dict:
    """
    Combines whatever live risk signals are available (OTP failures, geo/device
    anomaly, carding, bot-speed) into a single risk score, then returns an
    escalating action: ALLOW -> STEP_UP_REQUIRED -> BLOCK. This replaces a
    binary pass/fail MFA gate with one that scales the auth requirement to
    actual observed risk.
    """
    score = 0
    reasons = []

    if otp_result:
        if otp_result.get('status') == 'ALERT':
            score += AUTH_POLICY["adaptive_step_up"]["otp_alert_score"]
            reasons.append(f"{otp_result.get('failed_attempts', 0)} failed OTP attempts")
        elif otp_result.get('status') == 'WARN':
            score += AUTH_POLICY["adaptive_step_up"]["otp_warn_score"]
            reasons.append(f"{otp_result.get('failed_attempts', 0)} recent OTP failure(s)")

    if geo_result and geo_result.get('status') == 'ALERT':
        score += AUTH_POLICY["adaptive_step_up"]["geo_alert_score"]
        reasons.append('geolocation / device fingerprint anomaly')

    if carding_result and carding_result.get('status') == 'CARDING_RED_FLAG':
        score += AUTH_POLICY["adaptive_step_up"]["carding_score"]
        reasons.append('active carding pattern on this session')

    if bot_result:
        if bot_result.get('status') == 'BOT_RED_FLAG':
            score += AUTH_POLICY["adaptive_step_up"]["bot_red_flag_score"]
            reasons.append('bot-speed transaction automation')
        elif bot_result.get('status') == 'SUSPECT':
            score += AUTH_POLICY["adaptive_step_up"]["bot_suspect_score"]
            reasons.append('sub-human transaction timing')

    score = min(score, 100)
    if score >= AUTH_POLICY["adaptive_step_up"]["block_at"]:
        action = 'BLOCK'
    elif score >= AUTH_POLICY["adaptive_step_up"]["step_up_at"]:
        action = 'STEP_UP_REQUIRED'
    else:
        action = 'ALLOW'

    reason_str = f" ({'; '.join(reasons)})" if reasons else ""
    return {
        'action': action,
        'risk_score': score,
        'reasons': reasons,
        'details': f"Adaptive MFA risk score {score}/100 -> {action}{reason_str}."
    }


# --------------------------------------------------------------------------- #
# Problem 6 — Multi-IP & Geo-Velocity Anomalies (Haversine Impossible Travel)
# --------------------------------------------------------------------------- #

def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in km — same formula used for AIS vessel routing in ais_verification.py."""
    R = 6371.0
    phi1, phi2 = _math.radians(lat1), _math.radians(lat2)
    dphi = _math.radians(lat2 - lat1)
    dlambda = _math.radians(lon2 - lon1)
    a = _math.sin(dphi / 2) ** 2 + _math.cos(phi1) * _math.cos(phi2) * _math.sin(dlambda / 2) ** 2
    return 2 * R * _math.asin(min(1.0, _math.sqrt(a)))


def record_login_event(account_id: str, lat: float, lon: float, region: str = '', timestamp: float = None) -> dict:
    """
    Compares this login's location against the account's last known login
    location/time. If the implied travel speed between the two exceeds what's
    physically possible (faster than commercial air travel, over a non-trivial
    distance), flags impossible travel — e.g. Mumbai then Lagos minutes apart.
    """
    now = timestamp if timestamp is not None else _time.time()
    account_id = account_id or 'unknown_account'

    prev = _STORE.get_last(f'lastlogin:{account_id}')
    _STORE.set_last(f'lastlogin:{account_id}', now, value={'lat': lat, 'lon': lon, 'ts': now, 'region': region})

    if prev is None:
        return {'geo_velocity_anomaly': False, 'status': 'PASSED', 'distance_km': None,
                'implied_speed_kmh': None,
                'details': 'First login location recorded for this account; no prior location to compare.'}

    plat, plon, pts, pregion = prev['lat'], prev['lon'], prev['ts'], prev.get('region', '')
    dt_hours = max((now - pts) / 3600.0, 1e-6)
    dist_km = _haversine_km(plat, plon, lat, lon)
    speed_kmh = dist_km / dt_hours

    if dist_km >= AUTH_POLICY["impossible_travel_min_distance_km"] and speed_kmh > AUTH_POLICY["impossible_travel_speed_kmh"]:
        return {
            'geo_velocity_anomaly': True,
            'status': 'ALERT',
            'distance_km': round(dist_km, 1),
            'implied_speed_kmh': round(speed_kmh, 1),
            'details': (f"CRITICAL ALERT: Impossible travel velocity. {dist_km:.0f} km between logins "
                        f"({pregion or 'prior location'} -> {region or 'current location'}) in "
                        f"{dt_hours * 60:.1f} min implies {speed_kmh:.0f} km/h, exceeding the "
                        f"{AUTH_POLICY["impossible_travel_speed_kmh"]} km/h feasibility ceiling.")
        }

    return {
        'geo_velocity_anomaly': False,
        'status': 'PASSED',
        'distance_km': round(dist_km, 1),
        'implied_speed_kmh': round(speed_kmh, 1),
        'details': f"Login velocity plausible ({dist_km:.0f} km in {dt_hours * 60:.1f} min, {speed_kmh:.0f} km/h)."
    }


# --------------------------------------------------------------------------- #
# Legacy stateless / count-based checks — kept for backward compatibility and
# as the fallback path when the PoC demo-scenario dropdown is used instead of
# real live events.
# --------------------------------------------------------------------------- #

def evaluate_mfa_login_risk(failed_otp_attempts: int = 0, max_allowed: int = 3) -> dict:
    """Evaluates consecutive failed OTP / 2FA login submissions to prevent brute-force credential stuffing."""
    failed_cnt = max(0, int(failed_otp_attempts or 0))

    if failed_cnt >= max_allowed:
        return {
            'status': 'ALERT',
            'flag': 'MFA_LOCKOUT_RISK',
            'failed_attempts': failed_cnt,
            'max_allowed': max_allowed,
            'details': f"ALERT: High authentication risk! {failed_cnt} consecutive wrong OTP submissions exceeded threshold ({max_allowed}). Account temporarily locked."
        }

    return {
        'status': 'PASSED',
        'flag': 'NORMAL',
        'failed_attempts': failed_cnt,
        'max_allowed': max_allowed,
        'details': f"MFA authentication status normal ({failed_cnt}/{max_allowed} failed attempts)."
    }


def detect_device_geo_anomaly(typical_region: str = 'India', current_ip_region: str = 'India', device_fingerprint_match: bool = True) -> dict:
    """Checks if account request originates from an unrecognized geographic region without a matching trusted device fingerprint."""
    typ_reg = (typical_region or 'India').strip().upper()
    cur_reg = (current_ip_region or 'India').strip().upper()
    is_device_match = bool(device_fingerprint_match)

    geo_mismatch = (typ_reg != cur_reg)

    if geo_mismatch and not is_device_match:
        return {
            'geo_anomaly': True,
            'status': 'ALERT',
            'typical_region': typical_region,
            'current_ip_region': current_ip_region,
            'device_match': is_device_match,
            'details': f"ALERT: Geolocation anomaly detected! Session originating from unexpected region '{current_ip_region}' (account base: '{typical_region}') without recognized device fingerprint."
        }
    elif geo_mismatch and is_device_match:
        return {
            'geo_anomaly': False,
            'status': 'PASSED',
            'typical_region': typical_region,
            'current_ip_region': current_ip_region,
            'device_match': is_device_match,
            'details': f"Traveling user verified: Request from '{current_ip_region}' matched registered hardware device fingerprint."
        }

    return {
        'geo_anomaly': False,
        'status': 'PASSED',
        'typical_region': typical_region,
        'current_ip_region': current_ip_region,
        'device_match': is_device_match,
        'details': f"Geolocation and device fingerprint verified ({current_ip_region})."
    }


def detect_billing_carding_risk(consecutive_failed_payments: int = 0, attempts_window_sec: int = None) -> dict:
    """Legacy/demo adapter using the same external carding policy."""
    limit = CARDING_POLICY["same_payment_method_failures"]["count"]
    window = attempts_window_sec or CARDING_POLICY["same_payment_method_failures"]["window_seconds"]
    if consecutive_failed_payments >= limit:
        return {
            'carding_detected': True, 'status': 'CARDING_RED_FLAG',
            'failed_attempts': consecutive_failed_payments,
            'details': f"CARDING RED FLAG: {consecutive_failed_payments} back-to-back payment failures within {window}s."
        }
    return {
        'carding_detected': False, 'status': 'PASSED',
        'failed_attempts': consecutive_failed_payments,
        'details': f"Billing session clear ({consecutive_failed_payments} failed attempts)."
    }


def run_scout_security_audit(session_context: dict = None) -> dict:
    """
    Orchestrates Scout Account Security & Fraud Screening.
    Accepts session parameters:
    - failed_otp_attempts (int)
    - typical_region (str)
    - current_ip_region (str)
    - device_match (bool)
    - failed_card_payments (int)              -- used only if no live result is supplied
    - live_carding_result (dict, optional)     -- output of record_card_authorization()
    - live_bot_result (dict, optional)         -- output of record_transaction_event()

    When live_carding_result / live_bot_result are supplied (i.e. real payment
    attempt events have been recorded via record_card_authorization /
    record_transaction_event), those real, stateful detections are used.
    Otherwise this falls back to the count-based / demo-scenario path so the
    PoC scenario selector keeps working unchanged.
    """
    ctx = session_context or {}

    failed_otp  = ctx.get('failed_otp_attempts', 0)
    typ_region  = ctx.get('typical_region', 'India')
    cur_region  = ctx.get('current_ip_region', 'India')
    dev_match   = ctx.get('device_match', True)
    failed_pmts = ctx.get('failed_card_payments', 0)
    live_carding = ctx.get('live_carding_result')
    live_bot = ctx.get('live_bot_result')

    mfa_res = evaluate_mfa_login_risk(failed_otp)
    geo_res = detect_device_geo_anomaly(typ_region, cur_region, dev_match)
    carding_res = live_carding if live_carding is not None else detect_billing_carding_risk(failed_pmts)
    bot_res = live_bot if live_bot is not None else {
        'bot_detected': False, 'status': 'PASSED', 'gap_ms': None,
        'details': 'No transaction velocity events recorded for this session yet.'
    }

    if carding_res.get('status') == 'CARDING_RED_FLAG' or bot_res.get('status') == 'BOT_RED_FLAG':
        verdict = 'FRAUD_LOCKDOWN'
        badge = 'CARDING BLOCKED' if carding_res.get('status') == 'CARDING_RED_FLAG' else 'BOT BLOCKED'
        lockdown_reasons = [r['details'] for r in (carding_res, bot_res) if r.get('status') in ('CARDING_RED_FLAG', 'BOT_RED_FLAG')]
        summary = f"FRAUD LOCKDOWN: {' '.join(lockdown_reasons)}"
    elif mfa_res['status'] == 'ALERT' or geo_res['status'] == 'ALERT':
        verdict = 'ACCOUNT_ALERT'
        badge = 'MFA/GEO ALERT'
        alerts_list = []
        if mfa_res['status'] == 'ALERT': alerts_list.append(mfa_res['details'])
        if geo_res['status'] == 'ALERT': alerts_list.append(geo_res['details'])
        summary = f"ACCOUNT ALERT: Suspicious activity detected: {'; '.join(alerts_list)}"
    elif bot_res.get('status') == 'SUSPECT':
        verdict = 'ACCOUNT_ALERT'
        badge = 'BOT SUSPECT'
        summary = f"ACCOUNT ALERT: {bot_res['details']}"
    else:
        verdict = 'SECURE'
        badge = 'SECURE'
        summary = f"SECURE: Account authentication, device fingerprint, and billing session verified for account base {typ_region}."

    timestamp_str = datetime.now(timezone.utc).isoformat()

    return {
        'verdict': verdict,
        'badge': badge,
        'summary': summary,
        'mfa_audit': mfa_res,
        'geo_audit': geo_res,
        'carding_audit': carding_res,
        'bot_audit': bot_res,
        'timestamp': timestamp_str
    }


def incident_stats(now: float = None, window_seconds: float = 86400) -> dict:
    """Counts of fraud incidents in the last window, for the admin stats card (in memory, resets on restart)."""
    now = now if now is not None else _time.time()
    recent = [i for i in _INCIDENTS if now - i['at'] < window_seconds]
    return {'total': len(recent),
            'bot': sum(1 for i in recent if i['kind'] == 'bot'),
            'carding': sum(1 for i in recent if i['kind'] == 'carding'),
            'other': sum(1 for i in recent if i['kind'] not in ('bot', 'carding')),
            'repeat_locks': sum(1 for i in recent if i['level'] >= 2),
            'refs': [i['ref'] for i in recent]}
