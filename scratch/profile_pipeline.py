import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.getcwd())

import time, cv2, numpy as np
from local_extractor import run_ocr_fast, parse_trade_fields
from authenticity_engine import analyze_document_authenticity
from compliance_engine import evaluate_all_rules

print("=" * 60)
print("TRADEVERIFY PIPELINE DIAGNOSTIC REPORT")
print("=" * 60)

# Load test image
test_img_path = "CI.png" if os.path.exists("CI.png") else None
if not test_img_path:
    for root, dirs, files in os.walk("."):
        for f in files:
            if f.endswith((".png", ".jpg")) and "CI" in f:
                test_img_path = os.path.join(root, f)
                break

if not test_img_path:
    print("No sample image found to benchmark.")
    exit()

print(f"Profiling with test file: {test_img_path}")
with open(test_img_path, "rb") as f:
    img_bytes = f.read()

# Stage 1: Image Decode & Downsampling
t0 = time.perf_counter()
nparr = np.frombuffer(img_bytes, np.uint8)
img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
h, w = img.shape[:2]
if max(h, w) > 750:
    scale = 750.0 / max(h, w)
    img = cv2.resize(img, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
t_img = (time.perf_counter() - t0) * 1000

# Stage 2: OCR Inference
t0 = time.perf_counter()
text, boxes = run_ocr_fast(img_bytes)
t_ocr = (time.perf_counter() - t0) * 1000

# Stage 3: Regex Field Parsing
t0 = time.perf_counter()
fields = parse_trade_fields(text, "invoice")
t_parse = (time.perf_counter() - t0) * 1000

# Stage 4: Authenticity & Forensics (ELA / Benford's Law)
t0 = time.perf_counter()
auth_res = analyze_document_authenticity(img_bytes, "invoice", fields)
t_auth = (time.perf_counter() - t0) * 1000

# Stage 5: Compliance Rules & Sanctions Engine
t0 = time.perf_counter()
comp_res = evaluate_all_rules({"invoice": fields})
t_comp = (time.perf_counter() - t0) * 1000

print(f"1. Image Preprocessing  : {t_img:.2f} ms")
print(f"2. OCR Engine (RapidOCR): {t_ocr:.2f} ms")
print(f"3. Field Regex Parsing  : {t_parse:.2f} ms")
print(f"4. Forensics / Benford  : {t_auth:.2f} ms")
print(f"5. Compliance Evaluation: {t_comp:.2f} ms")
print("-" * 60)
print(f"TOTAL TIME PER DOC      : {(t_img + t_ocr + t_parse + t_auth + t_comp):.2f} ms")
print("=" * 60)
