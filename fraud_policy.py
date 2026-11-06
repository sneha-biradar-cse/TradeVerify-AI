"""Load and validate the external fraud policy. No fraud thresholds live in code."""
import json
import os
from pathlib import Path

DEFAULT_POLICY_PATH = Path(__file__).with_name("fraud_policy.json")


def _positive_number(value, name):
    if not isinstance(value, (int, float)) or value <= 0:
        raise ValueError(f"Policy field '{name}' must be a positive number")
    return value


def load_policy(path=None):
    policy_path = Path(path or os.environ.get("SCOUT_POLICY_FILE") or DEFAULT_POLICY_PATH)
    if not policy_path.is_absolute():
        policy_path = Path(__file__).resolve().parent / policy_path
    with policy_path.open("r", encoding="utf-8") as fh:
        policy = json.load(fh)

    carding = policy["carding"]
    bot = policy["bot"]
    scoring = policy["risk_scoring"]
    signals = scoring["signals"]
    decisions = scoring["decisions"]

    for section, values in (("carding", carding), ("bot", bot), ("risk_scoring.signals", signals), ("risk_scoring.decisions", decisions)):
        if not isinstance(values, dict):
            raise ValueError(f"Policy section '{section}' must be an object")
        for key, value in values.items():
            if isinstance(value, dict):
                for subkey, subvalue in value.items():
                    _positive_number(subvalue, f"{section}.{key}.{subkey}")
            else:
                _positive_number(value, f"{section}.{key}")

    if decisions["allow_below"] >= decisions["step_up_below"] or decisions["step_up_below"] >= decisions["review_below"] or decisions["review_below"] > decisions["block_at_or_above"]:
        raise ValueError("Risk decision thresholds must be strictly increasing")
    return policy


POLICY = load_policy()
