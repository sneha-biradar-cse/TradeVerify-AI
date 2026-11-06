import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from statistical_engine import (
    evaluate_benfords_law,
    detect_round_number_clustering,
    inspect_statistical_anomalies
)

print('=== 1. TESTING NATURAL BENFORD DISTRIBUTION (CONFORMING) ===')
# Natural dataset following Benford's law frequencies (30% 1s, 18% 2s, 12% 3s, etc.)
natural_numbers = [
    102.5, 14.8, 190.0, 1150.0, 1890.0, 12.5,
    21.4, 28.9, 290.0, 2450.0,
    31.0, 385.0, 39.0,
    45.0, 480.0,
    52.0,
    67.0,
    78.0,
    89.0,
    95.0
]
benford_natural = evaluate_benfords_law(natural_numbers)
print('Natural Benford Result:', json.dumps(benford_natural, indent=2))
assert benford_natural['status'] == 'PASSED'
assert benford_natural['mad_score'] <= 0.022

print('\n=== 2. TESTING ARTIFICIAL REPETITIVE DISTRIBUTION (DEVIATING) ===')
# Artificial dataset with all leading digits 5 and 9 (violating Benford's law)
artificial_numbers = [
    5000.0, 5500.0, 5200.0, 5900.0, 5100.0, 5300.0, 5800.0, 5400.0,
    9000.0, 9500.0, 9200.0, 9900.0, 9100.0, 9300.0, 9800.0, 9400.0
]
benford_artificial = evaluate_benfords_law(artificial_numbers)
print('Artificial Benford Result:', json.dumps(benford_artificial, indent=2))
assert benford_artificial['status'] == 'ANOMALY_DETECTED'
assert benford_artificial['mad_score'] > 0.022

print('\n=== 3. TESTING SMALL DATASET (INSUFFICIENT SAMPLE) ===')
small_numbers = [150.0, 250.0, 350.0]
benford_small = evaluate_benfords_law(small_numbers)
print('Small Sample Result:', json.dumps(benford_small, indent=2))
assert benford_small['status'] == 'UNAVAILABLE'
assert benford_small['sample_size'] == 3

print('\n=== 4. TESTING ROUND NUMBER CLUSTERING ===')
round_numbers = [100.0, 200.0, 500.0, 1000.0, 1500.0, 2000.0, 2500.0, 3000.0, 5000.0, 10000.0]
round_res = detect_round_number_clustering(round_numbers)
print('Round Clustering Result:', json.dumps(round_res, indent=2))
assert round_res['status'] == 'ANOMALY_DETECTED'
assert round_res['round_ratio'] == 1.0

print('\n=== 5. TESTING STATISTICAL ORCHESTRATOR ===')
dummy_fields = {
    'line_items': [
        {'unit_price': 102.5, 'total': 14.8},
        {'unit_price': 190.0, 'total': 1150.0},
        {'unit_price': 1890.0, 'total': 12.5},
        {'unit_price': 21.4, 'total': 28.9},
        {'unit_price': 290.0, 'total': 2450.0},
        {'unit_price': 31.0, 'total': 385.0}
    ]
}
stat_orch_res = inspect_statistical_anomalies(dummy_fields)
print('Statistical Orchestrator Result:', json.dumps(stat_orch_res, indent=2))
assert stat_orch_res['sample_size'] >= 10

print('\n[SUCCESS] ALL STATISTICAL ENGINE TESTS PASSED SUCCESSFULLY!')
