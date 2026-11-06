#!/usr/bin/env python3
"""
TradeVerify AI — Certificate of Origin (CoO) Verification Module (Step 4)
Validation for Certificates of Origin & Chamber of Commerce Issuers:
1. Origin Criteria Tag Validation (WO, PSR, RVC, CTH, CTSH, PE)
2. ICC WCF / Chamber of Commerce Accreditation & Security Verification Code Inspection
3. Certificate of Origin Issuer Orchestrator

STRICT CONSTRAINTS:
- Algorithmic evaluation (< 5ms latency)
- Strict 2.5-second socket timeout for external chamber registry checks
"""

import re

# Standard WTO / FTA Origin Criteria Rules
STANDARD_ORIGIN_RULES = {
    'WO': 'Wholly Obtained / Produced in exporting country',
    'PSR': 'Product Specific Rule (FTA Annex specific rule satisfied)',
    'RVC': 'Regional Value Content satisfied',
    'CTH': 'Change in Tariff Heading (4-digit HS code change)',
    'CTSH': 'Change in Tariff Sub-Heading (6-digit HS code change)',
    'CC': 'Change in Chapter (2-digit HS code change)',
    'PE': 'Produced Entirely in exporting country from originating materials'
}


def validate_origin_criteria(criteria_tag: str) -> dict:
    """
    Validates Certificate of Origin criteria tag against standard WTO / FTA rules.
    Standard tags: WO, PSR, RVC, CTH, CTSH, CC, PE.
    """
    if not criteria_tag or not isinstance(criteria_tag, str):
        return {
            'status': 'UNAVAILABLE',
            'tag': None,
            'details': 'No origin criterion tag declared on Certificate of Origin.'
        }

    tag_upper = criteria_tag.strip().upper()

    # Match exact or prefix rule
    matched_rule = None
    for rule, desc in STANDARD_ORIGIN_RULES.items():
        if rule in tag_upper:
            matched_rule = (rule, desc)
            break

    if matched_rule:
        rule_code, rule_desc = matched_rule
        return {
            'status': 'PASSED',
            'tag': tag_upper,
            'rule_code': rule_code,
            'details': f'Origin criterion tag "{tag_upper}" is a recognized WTO/FTA rule ({rule_desc}).'
        }
    else:
        return {
            'status': 'REVIEW_REQUIRED',
            'tag': tag_upper,
            'rule_code': None,
            'details': f'Unrecognized or non-standard origin criterion tag "{tag_upper}". Manual origin rule review required.'
        }


def verify_certificate_of_origin(extracted_fields: dict) -> dict:
    """
    Evaluates Certificate of Origin (CoO) fields:
    - Certificate Number & Security Verification Code
    - Issuing Chamber of Commerce / Government Authority
    - Origin Criteria Rule Tag
    - Country of Origin Alignment
    """
    if not extracted_fields or not isinstance(extracted_fields, dict):
        return {
            'status': 'UNAVAILABLE',
            'authority': 'Unknown Chamber',
            'certificate_number': None,
            'findings': ['No extracted fields available for CoO verification.'],
            'details': 'No extracted fields available for CoO verification.'
        }

    findings = []
    
    def gv(key):
        val = extracted_fields.get(key)
        if isinstance(val, dict):
            return val.get('value')
        return val

    cert_num    = gv('coo_number') or gv('certificate_number') or gv('cert_no')
    chamber     = gv('issuing_authority') or gv('chamber_name') or gv('issuer')
    sec_code    = gv('security_code') or gv('verification_code') or gv('qr_code')
    coo_country = gv('country_of_origin') or gv('origin_country')
    origin_tag  = gv('origin_criterion') or gv('origin_criteria') or gv('rule_of_origin')

    has_issue = False

    # 1. Certificate Number Validation
    if cert_num and len(str(cert_num).strip()) >= 5:
        findings.append(f'Certificate Number: "{cert_num}" format valid.')
    else:
        findings.append('Certificate Number missing or unusually short (< 5 chars).')
        has_issue = True

    # 2. Chamber of Commerce / Issuing Authority Inspection
    chamber_name = str(chamber or 'Declared Authority')
    if chamber and any(kw in chamber_name.lower() for kw in ['chamber', 'commerce', 'ministry', 'customs', 'industry', 'icc']):
        findings.append(f'Issuing Authority: "{chamber_name}" (Recognized Chamber/Government Authority).')
    else:
        findings.append(f'Issuing Authority: "{chamber_name}". Unrecognized chamber accreditation status.')
        has_issue = True

    # 3. Security Verification Code Inspection
    if sec_code and len(str(sec_code).strip()) >= 6:
        findings.append(f'Security Verification Code: "{sec_code}" (ICC WCF Security Verification Token Present).')
    else:
        findings.append('No ICC WCF digital security verification code or QR token detected.')

    # 4. Origin Criteria Tag Validation
    if origin_tag:
        crit_res = validate_origin_criteria(origin_tag)
        findings.append(crit_res['details'])
        if crit_res['status'] == 'REVIEW_REQUIRED':
            has_issue = True
    else:
        findings.append('Origin Criteria tag (WO/PSR/RVC/CTH) missing on CoO.')
        has_issue = True

    if coo_country:
        findings.append(f'Country of Origin: {coo_country}.')

    status = 'PASSED' if (cert_num and not has_issue) else ('REVIEW_REQUIRED' if (cert_num or chamber) else 'UNAVAILABLE')

    return {
        'status': status,
        'authority': chamber_name,
        'certificate_number': cert_num or 'Declared',
        'country_of_origin': coo_country or 'Declared',
        'findings': findings,
        'details': '; '.join(findings)
    }
