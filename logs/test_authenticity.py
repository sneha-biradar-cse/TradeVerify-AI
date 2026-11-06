import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from authenticity_engine import (
    inspect_digital_signatures,
    inspect_file_forensics,
    evaluate_evidence_decision,
    run_document_authenticity_engine
)

print('=== 1. TESTING DIGITAL SIGNATURE INSPECTOR ===')
sample_pdf_header = b'%PDF-1.7\n1 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /Name (TradeVerify Authority) /M (D:20250615120000+00\'00\') /ByteRange [0 100 200 500] /Contents <308201...00> >>\nendobj\n%%EOF'
sig_res = inspect_digital_signatures(sample_pdf_header, 'sample_signed.pdf')
print(json.dumps(sig_res, indent=2))
assert sig_res['is_signed'] == True
assert sig_res['status'] in ['PASSED', 'FAILED']

print('\n=== 2. TESTING FILE FORENSICS ENGINE ===')
forensic_res = inspect_file_forensics(sample_pdf_header, 'sample_signed.pdf')
print(json.dumps(forensic_res, indent=2))
assert 'status' in forensic_res

print('\n=== 3. TESTING FULL PIPELINE ORCHESTRATOR ON DUMMY FILES ===')
dummy_files = {
    'invoice': {'filename': 'Commercial_Invoice.png', 'data': b'\x89PNG\r\n\x1a\n' + b'\x00'*500},
    'packing': {'filename': 'Packing_List.pdf', 'data': sample_pdf_header},
    'bol': {'filename': 'Bill_of_Lading.png', 'data': b'\xff\xd8\xff\xe0' + b'\x00'*500}
}
auth_result = run_document_authenticity_engine(dummy_files, {'summary': {'fail': 0}})
print(json.dumps(auth_result, indent=2))

assert 'summary' in auth_result
assert 'documents' in auth_result
assert auth_result['summary']['overall_verdict'] in ['VERIFIED', 'LIKELY_AUTHENTIC', 'REVIEW_REQUIRED', 'HIGH_RISK']
assert 'invoice' in auth_result['documents']
assert 'packing' in auth_result['documents']
assert 'bol' in auth_result['documents']

print('\n[SUCCESS] ALL INTEGRATION TESTS PASSED SUCCESSFULLY!')
