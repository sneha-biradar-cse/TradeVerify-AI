import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from coo_verification import (
    validate_origin_criteria,
    verify_certificate_of_origin
)
from issuer_verification import verify_document_issuer
from authenticity_engine import run_document_authenticity_engine

print('=== 1. TESTING ORIGIN CRITERIA VALIDATION ===')
crit_valid_wo = validate_origin_criteria('WO')
print('WO Valid:', json.dumps(crit_valid_wo, indent=2))
assert crit_valid_wo['status'] == 'PASSED'

crit_valid_psr = validate_origin_criteria('PSR (Product Specific Rule)')
print('PSR Valid:', json.dumps(crit_valid_psr, indent=2))
assert crit_valid_psr['status'] == 'PASSED'

crit_invalid = validate_origin_criteria('UNKNOWN_RULE_99')
print('Invalid Rule:', json.dumps(crit_invalid, indent=2))
assert crit_invalid['status'] == 'REVIEW_REQUIRED'

print('\n=== 2. TESTING CERTIFICATE OF ORIGIN VERIFICATION ===')
valid_coo_fields = {
    'coo_number': {'value': 'COO-2026-884920'},
    'issuing_authority': {'value': 'International Chamber of Commerce & Industry'},
    'security_code': {'value': 'ICC-WCF-99204859'},
    'origin_criterion': {'value': 'WO'},
    'country_of_origin': {'value': 'India'}
}
coo_res = verify_certificate_of_origin(valid_coo_fields)
print('Valid CoO Result:', json.dumps(coo_res, indent=2))
assert coo_res['status'] == 'PASSED'
assert coo_res['certificate_number'] == 'COO-2026-884920'

print('\n=== 3. TESTING COO WITH UNRECOGNIZED ORIGIN CRITERION ===')
invalid_tag_fields = {
    'coo_number': {'value': 'COO-2026-884920'},
    'issuing_authority': {'value': 'Chamber of Commerce'},
    'origin_criterion': {'value': 'UNKNOWN_TAG'}
}
invalid_tag_res = verify_certificate_of_origin(invalid_tag_fields)
print('Unrecognized Origin Tag Result:', json.dumps(invalid_tag_res, indent=2))
assert invalid_tag_res['status'] == 'REVIEW_REQUIRED'

print('\n=== 4. TESTING ISSUER ORCHESTRATOR FOR COO ===')
issuer_coo_res = verify_document_issuer('coo', valid_coo_fields)
print('Issuer CoO Orchestration:', json.dumps(issuer_coo_res, indent=2))
assert issuer_coo_res['status'] == 'PASSED'
assert issuer_coo_res['source_type'] == 'Chamber of Commerce (ICC WCF)'

print('\n=== 5. TESTING END-TO-END PIPELINE WITH COO ===')
dummy_files = {
    'coo': {'filename': 'Certificate_of_Origin.pdf', 'data': b'%PDF-1.7\n%%EOF'}
}
dummy_extraction = {
    'coo': {'fields': valid_coo_fields}
}
pipeline_res = run_document_authenticity_engine(dummy_files, None, dummy_extraction)
print('Pipeline CoO Result:', json.dumps(pipeline_res, indent=2))

assert 'coo' in pipeline_res['documents']
assert pipeline_res['documents']['coo']['issuer_verification']['status'] == 'PASSED'

print('\n[SUCCESS] ALL COO VERIFICATION TESTS PASSED SUCCESSFULLY!')
