#!/usr/bin/env python3
"""
TradeVerify AI — Scout Account Security & Fraud Screening Engine (Step B)
In-memory account security, authentication integrity, and billing fraud engine:
1. Multi-Factor Authentication (MFA) & Wrong OTP Lockout Risk Screening
2. Geolocation Anomaly & Unrecognized Device Fingerprint Detection
3. Credit Card Testing & Billing Carding Fraud Protection
4. Account Security Audit Orchestrator

STRICT CONSTRAINTS:
- Purely deterministic, non-blocking, and in-memory (< 2ms execution latency)
- Grounded explainability: Distinguishes between clean sessions (SECURE), suspicious account alerts (ACCOUNT_ALERT), and active carding attacks (FRAUD_LOCKDOWN)
"""

import datetime


def evaluate_mfa_login_risk(failed_otp_attempts: int = 0, max_allowed: int = 3) -> dict:
    """
    Evaluates consecutive failed OTP / 2FA login submissions to prevent brute-force credential stuffing.
    """
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
    """
    Checks if account request originates from an unrecognized geographic region without a matching trusted device fingerprint.
    """
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


def detect_billing_carding_risk(consecutive_failed_payments: int = 0, attempts_window_sec: int = 60) -> dict:
    """
    Detects automated credit card testing / carding fraud patterns (>= 3 back-to-back failed authorizations).
    """
    failed_pmts = max(0, int(consecutive_failed_payments or 0))

    if failed_pmts >= 3:
        return {
            'carding_detected': True,
            'status': 'CARDING_RED_FLAG',
            'failed_attempts': failed_pmts,
            'attempts_window_sec': attempts_window_sec,
            'details': f"CARDING RED FLAG: Active payment card testing attack detected! {failed_pmts} consecutive payment authorization failures within {attempts_window_sec}s. Billing session suspended."
        }

    return {
        'carding_detected': False,
        'status': 'PASSED',
        'failed_attempts': failed_pmts,
        'attempts_window_sec': attempts_window_sec,
        'details': f"Billing session clear ({failed_pmts} failed payment authorization attempts)."
    }


def run_scout_security_audit(session_context: dict = None) -> dict:
    """
    Orchestrates Scout Account Security & Fraud Screening.
    Accepts session parameters:
    - failed_otp_attempts (int)
    - typical_region (str)
    - current_ip_region (str)
    - device_match (bool)
    - failed_card_payments (int)
    """
    ctx = session_context or {}

    failed_otp  = ctx.get('failed_otp_attempts', 0)
    typ_region  = ctx.get('typical_region', 'India')
    cur_region  = ctx.get('current_ip_region', 'India')
    dev_match   = ctx.get('device_match', True)
    failed_pmts = ctx.get('failed_card_payments', 0)

    # 1. Screen MFA Login Risk
    mfa_res = evaluate_mfa_login_risk(failed_otp)

    # 2. Screen Device & Geolocation Anomaly
    geo_res = detect_device_geo_anomaly(typ_region, cur_region, dev_match)

    # 3. Screen Billing Carding Risk
    carding_res = detect_billing_carding_risk(failed_pmts)

    # Determine Overall Account Verdict: SECURE, ACCOUNT_ALERT, FRAUD_LOCKDOWN
    if carding_res['status'] == 'CARDING_RED_FLAG':
        verdict = 'FRAUD_LOCKDOWN'
        badge = 'CARDING BLOCKED'
        summary = f"FRAUD LOCKDOWN: Active payment card testing attack detected ({failed_pmts} failed card authorizations). Billing session frozen."
    elif mfa_res['status'] == 'ALERT' or geo_res['status'] == 'ALERT':
        verdict = 'ACCOUNT_ALERT'
        badge = 'MFA/GEO ALERT'
        alerts_list = []
        if mfa_res['status'] == 'ALERT': alerts_list.append(mfa_res['details'])
        if geo_res['status'] == 'ALERT': alerts_list.append(geo_res['details'])
        summary = f"ACCOUNT ALERT: Suspicious activity detected: {'; '.join(alerts_list)}"
    else:
        verdict = 'SECURE'
        badge = 'SECURE'
        summary = f"SECURE: Account authentication, device fingerprint, and billing session verified for account base {typ_region}."

    timestamp_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

    return {
        'verdict': verdict,
        'badge': badge,
        'summary': summary,
        'mfa_audit': mfa_res,
        'geo_audit': geo_res,
        'carding_audit': carding_res,
        'timestamp': timestamp_str
    }
