import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from issuer_verification import (
    validate_iso6346_container,
    validate_imo_vessel,
    validate_tax_identifier,
    verify_bill_of_lading_source,
    verify_swift_bic,
    verify_document_issuer
)
from authenticity_engine import run_document_authenticity_engine

print('=== 0. TESTING SOLAS / IMO VESSEL CHECKSUM ===')
imo_valid = validate_imo_vessel('IMO 9387425')
print('IMO 9387425 Valid:', json.dumps(imo_valid, indent=2))
assert imo_valid['valid'] == True
assert imo_valid['status'] == 'PASSED'

imo_invalid = validate_imo_vessel('IMO 9387429')
print('IMO 9387429 Invalid:', json.dumps(imo_invalid, indent=2))
assert imo_invalid['valid'] == False
assert imo_invalid['status'] == 'FAILED'

print('=== 1. TESTING ISO 6346 CONTAINER CHECKSUM ===')
c_valid = validate_iso6346_container('CSQU3054383')
print('CSQU3054383:', json.dumps(c_valid, indent=2))
assert c_valid['valid'] == True

c_invalid = validate_iso6346_container('CSQU3054380') # Incorrect check digit 0 vs 3
print('CSQU3054380:', json.dumps(c_invalid, indent=2))
assert c_invalid['valid'] == False

print('\n=== 2. TESTING GSTIN & TAX IDENTIFIERS ===')
gst_valid = validate_tax_identifier('27AAAPL1234C1ZV', country='India')
print('GSTIN Valid:', json.dumps(gst_valid, indent=2))
assert gst_valid['status'] == 'PASSED'

gst_invalid = validate_tax_identifier('123456789012345', country='India')
print('GSTIN Invalid:', json.dumps(gst_invalid, indent=2))
assert gst_invalid['status'] == 'FAILED'

print('\n=== 3. TESTING SWIFT/BIC CODES ===')
swift_valid = verify_swift_bic('WFBIUS6S')
print('SWIFT Valid:', json.dumps(swift_valid, indent=2))
assert swift_valid['status'] == 'PASSED'

swift_invalid = verify_swift_bic('SHORT')
print('SWIFT Invalid:', json.dumps(swift_invalid, indent=2))
assert swift_invalid['status'] == 'FAILED'

print('\n=== 4. TESTING BILL OF LADING CARRIER SCAC REGISTRY ===')
bol_test = verify_bill_of_lading_source('MAEU987654321', container_number='CSQU3054383', carrier_name='Maersk Line')
print('B/L SCAC Match:', json.dumps(bol_test, indent=2))
assert bol_test['scac_code'] == 'MAEU'
assert bol_test['carrier'] == 'Maersk Line'
assert bol_test['status'] == 'PASSED'

print('\n=== 5. TESTING END-TO-END PIPELINE WITH ISSUER VERIFICATION ===')
dummy_files = {
    'bol': {'filename': 'Bill_of_Lading.pdf', 'data': b'%PDF-1.7\n%%EOF'}
}
dummy_extraction = {
    'bol': {
        'fields': {
            'bl_number': {'value': 'MAEU987654321'},
            'container_number': {'value': 'CSQU3054383'},
            'vessel_name': {'value': 'Maersk Line'}
        }
    }
}
pipeline_res = run_document_authenticity_engine(dummy_files, None, dummy_extraction)
print(json.dumps(pipeline_res, indent=2))

assert 'issuer_verification' in pipeline_res['documents']['bol']
assert pipeline_res['documents']['bol']['issuer_verification']['status'] == 'PASSED'

print('\n[SUCCESS] ALL ISSUER VERIFICATION TESTS PASSED SUCCESSFULLY!')
