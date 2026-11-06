import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ais_verification import (
    resolve_port_unlocode,
    calculate_nautical_distance,
    validate_voyage_feasibility,
    verify_vessel_telemetry
)
from authenticity_engine import run_document_authenticity_engine

print('=== 1. TESTING UN/LOCODE RESOLUTION ===')
nhava = resolve_port_unlocode('Nhava Sheva (JNPT)')
print('Nhava Sheva:', json.dumps(nhava, indent=2))
assert nhava['found'] == True
assert nhava['unlocode'] == 'INNSA'

rotterdam = resolve_port_unlocode('Rotterdam')
print('Rotterdam:', json.dumps(rotterdam, indent=2))
assert rotterdam['found'] == True
assert rotterdam['unlocode'] == 'NLRTM'

print('\n=== 2. TESTING NAUTICAL DISTANCE & FEASIBILITY ===')
# Distance between Nhava Sheva (18.95 N, 72.95 E) and Rotterdam (51.95 N, 4.15 E)
dist = calculate_nautical_distance(18.95, 72.95, 51.95, 4.15)
print(f'Nautical Distance (INNSA -> NLRTM): {dist} NM')
assert dist > 3000.0 # Great-circle distance is 3733.9 NM

feasibility_valid = validate_voyage_feasibility('Nhava Sheva', 'Rotterdam', '2026-03-01', '2026-03-25')
print('Feasibility Valid:', json.dumps(feasibility_valid, indent=2))
assert feasibility_valid['status'] == 'PASSED'
assert feasibility_valid['is_feasible'] == True

print('\n=== 3. TESTING IMPOSSIBLE TRANSIT TIME ===')
# 2 days to travel 5000 NM requires 100+ knots (physically impossible)
feasibility_impossible = validate_voyage_feasibility('Nhava Sheva', 'Rotterdam', '2026-03-01', '2026-03-03')
print('Feasibility Impossible:', json.dumps(feasibility_impossible, indent=2))
assert feasibility_impossible['status'] == 'REVIEW_REQUIRED'
assert feasibility_impossible['is_feasible'] == False

print('\n=== 4. TESTING AIS VESSEL TELEMETRY ===')
telemetry_res = verify_vessel_telemetry('MAERSK MC-KINNEY MOLLER', '9632064', 'Nhava Sheva', '2026-03-01')
print('AIS Telemetry Result:', json.dumps(telemetry_res, indent=2))
assert telemetry_res['status'] == 'PASSED'
assert telemetry_res['pol_unlocode'] == 'INNSA'

print('\n=== 5. TESTING END-TO-END B/L PIPELINE WITH AIS TELEMETRY ===')
dummy_files = {
    'bol': {'filename': 'Bill_of_Lading.pdf', 'data': b'%PDF-1.7\n%%EOF'}
}
dummy_extraction = {
    'bol': {
        'fields': {
            'bl_number': {'value': 'MAEU99204859'},
            'vessel_name': {'value': 'MAERSK MC-KINNEY MOLLER'},
            'imo_number': {'value': '9632064'},
            'port_of_loading': {'value': 'Nhava Sheva'},
            'port_of_discharge': {'value': 'Rotterdam'},
            'shipped_on_board_date': {'value': '2026-03-01'}
        }
    }
}
pipeline_res = run_document_authenticity_engine(dummy_files, None, dummy_extraction)
print('Pipeline B/L Result:', json.dumps(pipeline_res, indent=2))

assert 'telemetry_verification' in pipeline_res['documents']['bol']
assert pipeline_res['documents']['bol']['telemetry_verification']['status'] == 'PASSED'

print('\n[SUCCESS] ALL AIS MARINE TELEMETRY TESTS PASSED SUCCESSFULLY!')
