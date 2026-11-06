import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from account_scout import (
    evaluate_mfa_login_risk,
    detect_device_geo_anomaly,
    detect_billing_carding_risk,
    run_scout_security_audit
)

print('=== TEST 1: CLEAN LEGITIMATE ACCOUNT SESSION ===')
clean_session = {
    'failed_otp_attempts': 0,
    'typical_region': 'India',
    'current_ip_region': 'India',
    'device_match': True,
    'failed_card_payments': 0
}
clean_res = run_scout_security_audit(clean_session)
print('Clean Session Result:', json.dumps(clean_res, indent=2))
assert clean_res['verdict'] == 'SECURE'
assert clean_res['badge'] == 'SECURE'
assert clean_res['mfa_audit']['status'] == 'PASSED'
assert clean_res['geo_audit']['status'] == 'PASSED'
assert clean_res['carding_audit']['status'] == 'PASSED'

print('\n=== TEST 2: MFA BRUTE-FORCE OTP ATTACK ===')
mfa_session = {
    'failed_otp_attempts': 4,
    'typical_region': 'India',
    'current_ip_region': 'India',
    'device_match': True,
    'failed_card_payments': 0
}
mfa_res = run_scout_security_audit(mfa_session)
print('MFA Attack Result:', json.dumps(mfa_res, indent=2))
assert mfa_res['verdict'] == 'ACCOUNT_ALERT'
assert mfa_res['badge'] == 'MFA/GEO ALERT'
assert mfa_res['mfa_audit']['status'] == 'ALERT'
assert mfa_res['mfa_audit']['flag'] == 'MFA_LOCKOUT_RISK'

print('\n=== TEST 3: GEOLOCATION & UNRECOGNIZED DEVICE ANOMALY ===')
geo_session = {
    'failed_otp_attempts': 0,
    'typical_region': 'India',
    'current_ip_region': 'Africa',
    'device_match': False,
    'failed_card_payments': 0
}
geo_res = run_scout_security_audit(geo_session)
print('Geo Anomaly Result:', json.dumps(geo_res, indent=2))
assert geo_res['verdict'] == 'ACCOUNT_ALERT'
assert geo_res['geo_audit']['geo_anomaly'] == True
assert geo_res['geo_audit']['status'] == 'ALERT'

print('\n=== TEST 4: CREDIT CARD TESTING / CARDING FRAUD ATTACK ===')
carding_session = {
    'failed_otp_attempts': 0,
    'typical_region': 'India',
    'current_ip_region': 'India',
    'device_match': True,
    'failed_card_payments': 4
}
carding_res = run_scout_security_audit(carding_session)
print('Carding Attack Result:', json.dumps(carding_res, indent=2))
assert carding_res['verdict'] == 'FRAUD_LOCKDOWN'
assert carding_res['badge'] == 'CARDING BLOCKED'
assert carding_res['carding_audit']['carding_detected'] == True
assert carding_res['carding_audit']['status'] == 'CARDING_RED_FLAG'

print('\n[SUCCESS] ALL SCOUT ACCOUNT SECURITY & FRAUD ENGINE TESTS PASSED SUCCESSFULLY!')
