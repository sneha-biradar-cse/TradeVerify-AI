import os, sys, json, io
from PIL import Image
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from authenticity_engine import inspect_file_forensics, run_document_authenticity_engine

# Generate valid PNG image bytes in RAM
buf = io.BytesIO()
img = Image.new('RGB', (400, 400), color='white')
img.save(buf, format='PNG')
valid_png_bytes = buf.getvalue()

res = inspect_file_forensics(valid_png_bytes, 'invoice.png', 'image/png')
print('=== REAL PNG FORENSICS RESULT ===')
print(json.dumps(res, indent=2))
assert res['status'] == 'PASSED'
assert res['tamper_detected'] == False

print('\n[SUCCESS] REAL IMAGE FORENSIC TEST PASSED!')
