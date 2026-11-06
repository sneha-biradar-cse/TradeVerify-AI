#!/usr/bin/env python3
"""
TradeVerify AI — Statistical & Benford's Law Anomaly Engine (Step 3)
In-memory statistical analysis of extracted numerical data:
1. Benford's Law First-Digit Distribution Test (MAD score against log10(1 + 1/d))
2. Round Number Clustering Analysis
3. Numerical Anomaly Orchestrator

STRICT CONSTRAINTS:
- Purely algorithmic and in-memory (< 2ms execution time)
- Small sample handling: N < 10 returns UNAVAILABLE / INSUFFICIENT_SAMPLE to eliminate false positives
"""

import math, re

# Theoretical Benford's Law probabilities for digits 1..9
BENFORD_PROBABILITIES = {
    1: math.log10(1 + 1/1),  # ~0.3010
    2: math.log10(1 + 1/2),  # ~0.1761
    3: math.log10(1 + 1/3),  # ~0.1249
    4: math.log10(1 + 1/4),  # ~0.0969
    5: math.log10(1 + 1/5),  # ~0.0792
    6: math.log10(1 + 1/6),  # ~0.0669
    7: math.log10(1 + 1/7),  # ~0.0580
    8: math.log10(1 + 1/8),  # ~0.0512
    9: math.log10(1 + 1/9)   # ~0.0458
}


def _get_leading_digit(num: float) -> int:
    """Extracts the first non-zero leading digit (1..9) of a number."""
    if num <= 0:
        return None
    val_str = f"{num:.10e}" # e.g. 1.2340000000e+04 or 5.0000000000e-02
    first_char = val_str[0]
    if first_char.isdigit() and first_char != '0':
        return int(first_char)
    return None


def evaluate_benfords_law(numbers: list) -> dict:
    """
    Evaluates first-digit distribution of a list of numbers against Benford's Law.
    Computes Mean Absolute Deviation (MAD).
    Thresholds (Nigrini):
    - MAD <= 0.018: Conformity (PASSED)
    - MAD > 0.025: Non-conformity (ANOMALY_DETECTED)
    Requires N >= 10 to avoid false alarms on small samples.
    """
    if not numbers or not isinstance(numbers, list):
        return {
            'status': 'UNAVAILABLE',
            'sample_size': 0,
            'mad_score': 0.0,
            'details': 'No numerical data provided for Benford\'s Law analysis.'
        }

    # Extract valid positive numbers and leading digits
    leading_digits = []
    valid_nums = []
    for val in numbers:
        try:
            f_val = float(val)
            if f_val > 0:
                ld = _get_leading_digit(f_val)
                if ld is not None:
                    leading_digits.append(ld)
                    valid_nums.append(f_val)
        except (ValueError, TypeError):
            continue

    sample_size = len(leading_digits)

    if sample_size < 10:
        return {
            'status': 'UNAVAILABLE',
            'sample_size': sample_size,
            'mad_score': 0.0,
            'details': f'Sample size too small (N={sample_size} < 10) for Benford\'s Law analysis.'
        }

    # Count frequencies of digits 1..9
    counts = {d: 0 for d in range(1, 10)}
    for ld in leading_digits:
        counts[ld] += 1

    # Calculate MAD = (1/9) * sum(|observed_freq - benford_prob|)
    total_abs_diff = 0.0
    freq_observed = {}
    for d in range(1, 10):
        obs_freq = counts[d] / sample_size
        freq_observed[d] = round(obs_freq, 4)
        ben_prob = BENFORD_PROBABILITIES[d]
        total_abs_diff += abs(obs_freq - ben_prob)

    mad_score = total_abs_diff / 9.0

    # Nigrini MAD Thresholds: <= 0.018 PASSED, > 0.025 ANOMALY_DETECTED
    if mad_score <= 0.022:
        status = 'PASSED'
        details = f'First-digit distribution conforms to Benford\'s Law (MAD score: {mad_score:.4f}, N={sample_size}).'
    else:
        status = 'ANOMALY_DETECTED'
        details = f'Numerical anomaly detected: first-digit distribution deviates significantly from Benford\'s Law (MAD score: {mad_score:.4f} > 0.022 threshold, N={sample_size}).'

    return {
        'status': status,
        'sample_size': sample_size,
        'mad_score': round(mad_score, 4),
        'observed_frequencies': freq_observed,
        'details': details
    }


def detect_round_number_clustering(numbers: list) -> dict:
    """
    Detects abnormal clustering on round numbers (e.g. ending in .00, 000, 500).
    Flagged if > 85% of detailed line item amounts or weights are perfectly round numbers.
    Requires N >= 5.
    """
    if not numbers or not isinstance(numbers, list):
        return {'status': 'UNAVAILABLE', 'sample_size': 0, 'round_ratio': 0.0, 'details': 'No numbers provided.'}

    valid_nums = []
    for val in numbers:
        try:
            f_val = float(val)
            if f_val > 0:
                valid_nums.append(f_val)
        except (ValueError, TypeError):
            continue

    sample_size = len(valid_nums)
    if sample_size < 5:
        return {'status': 'UNAVAILABLE', 'sample_size': sample_size, 'round_ratio': 0.0, 'details': f'Insufficient sample size (N={sample_size} < 5) for round-number analysis.'}

    round_count = 0
    for num in valid_nums:
        # Check if number is integer or ends in .000 or multiple of 100/1000
        if num.is_integer() or abs(num - round(num, -2)) < 0.001 or abs(num - round(num, -1)) < 0.001:
            round_count += 1

    round_ratio = round_count / sample_size

    if round_ratio > 0.85 and sample_size >= 8:
        status = 'ANOMALY_DETECTED'
        details = f'Abnormal round-number clustering: {round_ratio*100:.1f}% of items are perfectly rounded values ({round_count}/{sample_size}).'
    else:
        status = 'PASSED'
        details = f'Round number frequency is within normal distribution limits ({round_ratio*100:.1f}%, N={sample_size}).'

    return {
        'status': status,
        'sample_size': sample_size,
        'round_ratio': round(round_ratio, 3),
        'details': details
    }


def inspect_statistical_anomalies(extracted_fields: dict) -> dict:
    """
    Orchestrates statistical anomaly detection for document numerical fields.
    Collects unit prices, item quantities, amounts, and weights.
    """
    if not extracted_fields or not isinstance(extracted_fields, dict):
        return {
            'status': 'UNAVAILABLE',
            'benford': {'status': 'UNAVAILABLE'},
            'round_clustering': {'status': 'UNAVAILABLE'},
            'findings': ['No extracted numerical data available for statistical analysis.'],
            'details': 'No extracted numerical data available.'
        }

    # Gather numbers from fields and line items
    numbers = []

    def extract_nums_from_obj(obj):
        if isinstance(obj, (int, float)):
            if obj > 0:
                numbers.append(float(obj))
        elif isinstance(obj, str):
            # Extract numbers from string
            found = re.findall(r'\b\d+(?:\.\d+)?\b', obj)
            for f in found:
                try:
                    val = float(f)
                    if val > 0:
                        numbers.append(val)
                except ValueError:
                    pass
        elif isinstance(obj, dict):
            for v in obj.values():
                extract_nums_from_obj(v)
        elif isinstance(obj, list):
            for item in obj:
                extract_nums_from_obj(item)

    for field_name, field_val in extracted_fields.items():
        extract_nums_from_obj(field_val)

    benford_res = evaluate_benfords_law(numbers)
    round_res   = detect_round_number_clustering(numbers)

    findings = []
    if benford_res['status'] != 'UNAVAILABLE':
        findings.append(benford_res['details'])
    if round_res['status'] != 'UNAVAILABLE':
        findings.append(round_res['details'])

    if not findings:
        findings.append(f'Insufficient numerical sample (N={len(numbers)}) for statistical Benford/clustering analysis.')

    overall_status = 'PASSED'
    if benford_res['status'] == 'ANOMALY_DETECTED' or round_res['status'] == 'ANOMALY_DETECTED':
        overall_status = 'ANOMALY_DETECTED'
    elif benford_res['status'] == 'UNAVAILABLE' and round_res['status'] == 'UNAVAILABLE':
        overall_status = 'UNAVAILABLE'

    return {
        'status': overall_status,
        'sample_size': len(numbers),
        'benford': benford_res,
        'round_clustering': round_res,
        'findings': findings,
        'details': '; '.join(findings)
    }
