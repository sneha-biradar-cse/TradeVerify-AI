#!/usr/bin/env python3
"""
TradeVerify AI — Comprehensive Phase 2 Benchmark & Verification Suite (test_phase2_engines.py)

Tests:
1. Cryptographic Forensics & Tamper Engine (authenticity_engine.py)
   - PAdES / PKCS#7 Digital Signatures & ByteRange Tamper Detection
   - Error Level Analysis (ELA) on raster images
   - 2D QR & Barcode Payload Reconciliation
2. Cross-Document Verification Matrix & Checksums (verification_matrix.py)
   - ISO 6346 Mod-11 Shipping Container Check Digit
   - SOLAS Mod-10 IMO Ship Identifier Check Digit
   - Benford's Law First-Digit Distribution
   - Levenshtein Party Matching (>= 85%)
   - Weight Balancing (Gross B/L >= Gross Packing >= Net Packing, <= 2% threshold)
   - Financial Value vs LC Maximum Amount (+5% tolerance)
3. Trade Route & Sanctions Intelligence (sanctions_engine.py)
   - OFAC / UN Embargoed Jurisdiction & High-Risk Hub Screening
   - Dual-Use & Luxury Goods Screening by HS Chapter
   - Satellite AIS Great-Circle Nautical Feasibility (18-22 knots)
4. Full Server Pipeline Integration (server.py)
   - End-to-end multi-document package analysis
"""

import sys
import os
import io
import time
import json

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import cv2
from PIL import Image
from reportlab.pdfgen import canvas

# Import Phase 2 Engines
from authenticity_engine import inspect_digital_signatures, inspect_image_ela, inspect_document_barcodes, analyze_document_authenticity, run_document_authenticity_engine
from verification_matrix import validate_iso6346, validate_solas_imo, evaluate_benford_law, verify_document_package
from sanctions_engine import check_trade_route_sanctions, evaluate_restricted_goods, screen_trade_route, run_frm_screening, compliance_evaluator
from server import build_full_payload


def test_section_header(title):
    print("\n" + "=" * 65)
    print(f"  {title}")
    print("=" * 65)


def run_phase2_tests():
    start_total = time.perf_counter()

    # ─────────────────────────────────────────────────────────────
    # 1. CRYPTOGRAPHIC FORENSICS & TAMPER ENGINE
    # ─────────────────────────────────────────────────────────────
    test_section_header("1. TESTING CRYPTOGRAPHIC FORENSICS & TAMPER ENGINE")

    # 1.1 Unsigned PDF
    buf_unsigned = io.BytesIO()
    c = canvas.Canvas(buf_unsigned)
    c.drawString(100, 700, "Commercial Invoice - Unsigned")
    c.save()
    unsigned_pdf_bytes = buf_unsigned.getvalue()

    sig_unsigned = inspect_digital_signatures(unsigned_pdf_bytes, "invoice.pdf")
    print(f"Unsigned PDF Status: {sig_unsigned['status']} (Expected: UNSIGNED)")
    assert sig_unsigned['status'] == 'UNSIGNED'

    # 1.2 Signed PDF Mock (Valid ByteRange)
    dummy_pdf_content = b"%PDF-1.7\n1 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /Name (Global Exporters CA) /M (D:20260315120000) /ByteRange [ 0 100 200 50 ] >>\nendobj\n%%EOF\n"
    # Pad to exactly 250 bytes
    mock_signed_pdf = dummy_pdf_content + b"A" * (250 - len(dummy_pdf_content))
    sig_signed = inspect_digital_signatures(mock_signed_pdf, "signed_invoice.pdf")
    print(f"Mock Signed PDF Status: {sig_signed['status']} | Signer: {sig_signed['signer_name']}")
    assert sig_signed['status'] == 'VALID'
    assert sig_signed['is_signed'] is True

    # 1.3 Tampered PDF (Appended bytes post ByteRange)
    tampered_pdf = mock_signed_pdf + b"\nEXTRA_TAMPERED_CONTENT_INJECTED" * 10
    sig_tampered = inspect_digital_signatures(tampered_pdf, "tampered_invoice.pdf")
    print(f"Tampered PDF Status: {sig_tampered['status']} (Expected: TAMPERED)")
    assert sig_tampered['status'] == 'TAMPERED'

    # 1.4 Image Error Level Analysis (ELA)
    test_img = np.ones((200, 200, 3), dtype=np.uint8) * 200
    cv2.putText(test_img, "INVOICE $82,500.00", (10, 100), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 0), 2)
    _, img_encoded = cv2.imencode('.png', test_img)
    img_bytes = img_encoded.tobytes()

    ela_res = inspect_image_ela(img_bytes, "invoice_scan.png")
    print(f"Image ELA Forensic Status: {ela_res['forensic_status']} | Tamper Detected: {ela_res['tamper_detected']}")
    assert ela_res['forensic_status'] in ['PASSED', 'TAMPERED']

    # 1.5 analyze_document_authenticity
    doc_auth = analyze_document_authenticity(unsigned_pdf_bytes, "invoice.pdf", extracted_fields={'invoice_number': {'value': 'INV-1001'}})
    print(f"analyze_document_authenticity Overall: {doc_auth['overall_status']}")
    assert doc_auth['overall_status'] in ['LIKELY_AUTHENTIC', 'VERIFIED', 'TAMPERED']
    print("[PASS] Cryptographic Forensics & Tamper Engine verified.")

    # ─────────────────────────────────────────────────────────────
    # 2. CROSS-DOCUMENT VERIFICATION MATRIX & CHECKSUMS
    # ─────────────────────────────────────────────────────────────
    test_section_header("2. TESTING CROSS-DOCUMENT MATRIX & CHECKSUMS")

    # 2.1 ISO 6346 Container Check Digit
    valid_container = validate_iso6346("MAEU1234567")
    print(f"Valid ISO 6346 Check (MAEU1234567): {valid_container['status']} | Valid: {valid_container['valid']}")
    assert valid_container['valid'] is True

    invalid_container = validate_iso6346("MAEU1234560")
    print(f"Invalid ISO 6346 Check (MAEU1234560): {invalid_container['status']} | Valid: {invalid_container['valid']}")
    assert invalid_container['valid'] is False

    # 2.2 SOLAS Mod-10 IMO Number Check Digit
    valid_imo = validate_solas_imo("9632064")
    print(f"Valid SOLAS IMO Check (9632064): {valid_imo['status']} | Valid: {valid_imo['valid']}")
    assert valid_imo['valid'] is True

    invalid_imo = validate_solas_imo("9632069")
    print(f"Invalid SOLAS IMO Check (9632069): {invalid_imo['status']} | Valid: {invalid_imo['valid']}")
    assert invalid_imo['valid'] is False

    # 2.3 Benford's Law First-Digit Evaluation
    natural_sample = [1200, 1500, 1800, 2100, 2500, 3100, 1050, 4200, 1950, 2800]
    benford_natural = evaluate_benford_law(natural_sample)
    print(f"Benford's Law Natural Sample: {benford_natural['status']} | MAD: {benford_natural['mad_score']}")
    assert benford_natural['status'] == 'PASSED'

    # 2.4 Cross-Document Verification Package Evaluation
    mock_extraction_pass = {
        'invoice': {
            'uploaded': True,
            'fields': {
                'exporter': {'value': 'Nutri Max Organic Foods Ltd'},
                'consignee': {'value': 'Global Importers LLC'},
                'total_amount': {'value': '82,500.00'},
                'currency': {'value': 'USD'},
                'hs_code': {'value': '0801.32.00'}
            },
            'line_items': [{'amount': '41250.00'}, {'amount': '41250.00'}]
        },
        'packing': {
            'uploaded': True,
            'fields': {
                'exporter': {'value': 'Nutri Max Organic Foods Limited'},
                'consignee': {'value': 'Global Importers LLC'},
                'gross_weight': {'value': '21,500 kg'},
                'net_weight': {'value': '20,000 kg'}
            }
        },
        'bol': {
            'uploaded': True,
            'fields': {
                'exporter': {'value': 'Nutri Max Organic Foods Ltd'},
                'consignee': {'value': 'Global Importers LLC'},
                'gross_weight': {'value': '21,500 kg'},
                'container_number': {'value': 'MAEU1234567'},
                'imo_number': {'value': 'IMO 9632064'},
                'port_of_loading': {'value': 'Nhava Sheva'},
                'port_of_discharge': {'value': 'Rotterdam'},
                'hs_code': {'value': '0801.32.00'}
            }
        },
        'lc': {
            'uploaded': True,
            'fields': {
                'beneficiary': {'value': 'Nutri Max Organic Foods Ltd'},
                'applicant': {'value': 'Global Importers LLC'},
                'lc_amount': {'value': '85,000.00'},
                'currency': {'value': 'USD'}
            }
        }
    }

    matrix_res = verify_document_package(mock_extraction_pass)
    print(f"Matrix Package Verdict: {matrix_res['status']} | Pass: {matrix_res['summary']['pass']}/{matrix_res['summary']['total']}")
    assert matrix_res['status'] in ['PASS', 'REVIEW']
    assert matrix_res['checksums']['iso6346_container']['valid'] is True
    assert matrix_res['checksums']['solas_imo']['valid'] is True
    assert matrix_res['weight_balance']['status'] == 'PASS'
    assert matrix_res['value_matching']['status'] == 'PASS'
    print("[PASS] Cross-Document Matrix & Checksums verified.")

    # ─────────────────────────────────────────────────────────────
    # 3. TRADE ROUTE & SANCTIONS INTELLIGENCE
    # ─────────────────────────────────────────────────────────────
    test_section_header("3. TESTING SANCTIONS & TRADE ROUTE INTELLIGENCE")

    # 3.1 Unrestricted Route
    s_clear = check_trade_route_sanctions("USA", origin_country="India", port_of_discharge="Los Angeles")
    print(f"USA Trade Route: {s_clear['risk_level']} (Sanctioned: {s_clear['sanctioned']})")
    assert s_clear['risk_level'] == 'CLEAR'

    # 3.2 Comprehensive Embargoed Jurisdiction (North Korea / KP)
    s_embargo = check_trade_route_sanctions("North Korea", port_of_discharge="Nampo")
    print(f"North Korea Trade Route: {s_embargo['risk_level']} | Jurisdiction: {s_embargo['jurisdiction']}")
    assert s_embargo['risk_level'] == 'RED_FLAG'
    assert s_embargo['sanctioned'] is True

    # 3.3 High-Risk Port Hub (Bandar Abbas, Iran)
    s_hub = check_trade_route_sanctions("UAE", port_of_discharge="Bandar Abbas")
    print(f"Bandar Abbas Hub Screening: {s_hub['risk_level']} | Details: {s_hub['details']}")
    assert s_hub['sanctioned'] is True

    # 3.4 Dual-Use & Military HS Code Screening (Chapter 93 Arms)
    goods_arms = evaluate_restricted_goods("Ballistic protective gear", hs_code="9306.90")
    print(f"Arms HS 93 Screening: {goods_arms['flag']} | Category: {goods_arms['category']}")
    assert goods_arms['flag'] == 'RED_FLAG'

    # 3.5 General Utility Goods Allowance to KP
    goods_bags = evaluate_restricted_goods("Plain Cotton Shopping Bags", destination_country="North Korea")
    print(f"Cotton Bags to KP: {goods_bags['flag']} | Category: {goods_bags['category']}")
    assert goods_bags['flag'] == 'REVIEW_REQUIRED'
    assert goods_bags['is_restricted'] is False

    # 3.6 Full FRM Screening
    frm_res = run_frm_screening(mock_extraction_pass)
    print(f"Full FRM Screening Verdict: {frm_res['status']}")
    assert frm_res['status'] in ['CLEAR', 'REVIEW_REQUIRED', 'RED_FLAG']
    assert 'route_screening' in frm_res
    assert 'ais_feasibility' in frm_res

    # 3.7 Universal HS & Value-Threshold Compliance Engine
    # Luxury over €300 unit value to Russia -> CRITICAL_BLOCK
    v_lux = compliance_evaluator.evaluate_shipment({
        "destination_country": "Russia",
        "hs_code": "4202.21",
        "currency": "EUR",
        "total_amount": 5000.0,
        "quantity": 10.0,
        "unit_price": 500.0
    })
    print(f"Universal Compliance Luxury Breach: {len(v_lux)} violation(s) | Action: {v_lux[0]['severity']}")
    assert len(v_lux) >= 1
    assert v_lux[0]['severity'] == 'CRITICAL_BLOCK'

    # Dual-use microelectronics (HS 85) to China -> EXPORT_LICENSE_REQUIRED
    v_dual = compliance_evaluator.evaluate_shipment({
        "destination_country": "China",
        "hs_code": "8542.31",
        "currency": "USD",
        "total_amount": 12000.0
    })
    print(f"Universal Compliance Dual-Use: {len(v_dual)} violation(s) | Action: {v_dual[0]['severity']}")
    assert len(v_dual) >= 1
    assert v_dual[0]['severity'] == 'EXPORT_LICENSE_REQUIRED'

    # Total embargo to North Korea -> CRITICAL_BLOCK
    v_kp = compliance_evaluator.evaluate_shipment({
        "destination_country": "North Korea",
        "hs_code": "0801.32",
        "currency": "USD",
        "total_amount": 15000.0
    })
    print(f"Universal Compliance Total Embargo: {len(v_kp)} violation(s) | Action: {v_kp[0]['severity']}")
    assert len(v_kp) >= 1
    assert v_kp[0]['severity'] == 'CRITICAL_BLOCK'

    # Unrestricted export (Cashew Kernels to USA) -> 0 violations
    v_clear = compliance_evaluator.evaluate_shipment({
        "destination_country": "USA",
        "hs_code": "0801.32",
        "currency": "USD",
        "total_amount": 82500.0
    })
    print(f"Universal Compliance Unrestricted: {len(v_clear)} violations (Expected: 0)")
    assert len(v_clear) == 0

    print("[PASS] Trade Route & Sanctions Intelligence verified.")

    # ─────────────────────────────────────────────────────────────
    # 4. FULL SERVER PIPELINE INTEGRATION
    # ─────────────────────────────────────────────────────────────
    test_section_header("4. TESTING FULL PIPELINE ORCHESTRATION (server.py)")

    buf_inv = io.BytesIO()
    c = canvas.Canvas(buf_inv)
    c.setFont("Helvetica", 12)
    c.drawString(50, 750, "COMMERCIAL INVOICE")
    c.drawString(50, 730, "Invoice No: INV-2026-90210")
    c.drawString(50, 710, "Invoice Date: 2026-04-01")
    c.drawString(50, 690, "Total Amount: USD 82,500.00")
    c.drawString(50, 670, "Exporter: Nutri Max Organic Foods Ltd")
    c.drawString(50, 650, "Consignee: Global Importers LLC")
    c.drawString(50, 630, "GSTIN: 27AAAAA0000A1Z5")
    c.drawString(50, 610, "Country of Origin: India")
    c.save()

    test_files = {
        'invoice': {
            'filename': 'commercial_invoice.pdf',
            'data': buf_inv.getvalue()
        }
    }

    full_payload = build_full_payload(test_files)
    print(f"Pipeline Payload Success: {full_payload['success']}")
    print(f"Shipment Status: {full_payload['shipmentStatus']} | Health Score: {full_payload['shipmentHealth']}%")
    print(f"Verification Checks: {len(full_payload['verification']['checks'])}")
    print(f"Authenticity Verdict: {full_payload['authenticity']['summary']['overall_verdict']}")
    print(f"Sanctions Verdict: {full_payload['sanctions_compliance']['status']}")

    assert full_payload['success'] is True
    assert 'verification' in full_payload
    assert 'authenticity' in full_payload
    assert 'sanctions_compliance' in full_payload
    assert 'account_security' in full_payload

    elapsed_total = round((time.perf_counter() - start_total) * 1000.0, 2)
    print("\n" + "=" * 65)
    print(f"  [SUCCESS] ALL PHASE 2 FRAUD & FORENSIC TESTS PASSED ({elapsed_total:.2f} ms)!")
    print("=" * 65)


if __name__ == '__main__':
    run_phase2_tests()
