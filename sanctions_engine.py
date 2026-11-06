#!/usr/bin/env python3
"""
TradeVerify AI — Trade Route & Sanctions Intelligence Engine (Phase 2)
FRM (Fraud & Risk Management) & Sanctions Intelligence Engine evaluating:
1. Trade Route & Embargoed Jurisdiction Screening (KP, IR, SY, CU, RU, High-Risk Hubs)
2. Granular Commodity & Dual-Use / Luxury Goods Screening (UN Chapter VII, OFAC & HS Chapter Codes)
3. Satellite AIS Marine Telemetry Feasibility (Haversine Great-Circle Nautical Distance & 18-22 Knot Cruising Feasibility)
4. Comprehensive Route & Compliance Reporting (screen_trade_route & run_frm_screening)

STRICT CONSTRAINTS:
- 100% In-Memory & Deterministic Execution (< 5ms latency)
- Zero external cloud dependencies
"""

import re
from typing import Dict, List, Any
from datetime import datetime, timezone
from ais_verification import validate_voyage_feasibility, resolve_port_unlocode

# Embargoed & High-Risk Jurisdictions Database
SANCTIONED_JURISDICTIONS = {
    'KP': {'name': 'North Korea (DPRK)', 'code': 'KP', 'risk': 'EMBARGOED', 'description': 'Comprehensive UN & OFAC Sanctions (UN SCR 1718/2094/2270)'},
    'DPRK': {'name': 'North Korea (DPRK)', 'code': 'KP', 'risk': 'EMBARGOED', 'description': 'Comprehensive UN & OFAC Sanctions (UN SCR 1718/2094/2270)'},
    'NORTH KOREA': {'name': 'North Korea (DPRK)', 'code': 'KP', 'risk': 'EMBARGOED', 'description': 'Comprehensive UN & OFAC Sanctions (UN SCR 1718/2094/2270)'},
    'IR': {'name': 'Iran', 'code': 'IR', 'risk': 'EMBARGOED', 'description': 'Comprehensive OFAC & EU Sanctions (31 CFR Part 560)'},
    'IRAN': {'name': 'Iran', 'code': 'IR', 'risk': 'EMBARGOED', 'description': 'Comprehensive OFAC & EU Sanctions (31 CFR Part 560)'},
    'SY': {'name': 'Syria', 'code': 'SY', 'risk': 'EMBARGOED', 'description': 'Comprehensive OFAC & EU Sanctions (31 CFR Part 542)'},
    'SYRIA': {'name': 'Syria', 'code': 'SY', 'risk': 'EMBARGOED', 'description': 'Comprehensive OFAC & EU Sanctions (31 CFR Part 542)'},
    'CU': {'name': 'Cuba', 'code': 'CU', 'risk': 'EMBARGOED', 'description': 'Comprehensive OFAC CACR Sanctions (31 CFR Part 515)'},
    'CUBA': {'name': 'Cuba', 'code': 'CU', 'risk': 'EMBARGOED', 'description': 'Comprehensive OFAC CACR Sanctions (31 CFR Part 515)'},
    'RU': {'name': 'Russia', 'code': 'RU', 'risk': 'HIGH_RISK_SECTORAL', 'description': 'OFAC & EU Sectoral Sanctions & Export Control List'},
    'RUSSIA': {'name': 'Russia', 'code': 'RU', 'risk': 'HIGH_RISK_SECTORAL', 'description': 'OFAC & EU Sectoral Sanctions & Export Control List'},
    'CRIMEA': {'name': 'Crimea Region', 'code': 'UA-CRI', 'risk': 'EMBARGOED', 'description': 'OFAC Comprehensive Sanctions on Occupied Territories'}
}

# High-Risk Transshipment Seaports & Hubs
HIGH_RISK_HUBS = {
    'BANDAR ABBAS': {'country': 'Iran', 'risk': 'EMBARGOED_PORT'},
    'LATAKIA': {'country': 'Syria', 'risk': 'EMBARGOED_PORT'},
    'NAMPO': {'country': 'North Korea', 'risk': 'EMBARGOED_PORT'},
    'VLADIVOSTOK': {'country': 'Russia', 'risk': 'HIGH_RISK_PORT'},
    'NOVOROSSIYSK': {'country': 'Russia', 'risk': 'HIGH_RISK_PORT'},
    'SEVASTOPOL': {'country': 'Crimea', 'risk': 'EMBARGOED_PORT'}
}

# Luxury Goods Keywords
LUXURY_KEYWORDS = [
    'luxury', 'designer', 'rolex', 'gucci', 'prada', 'louis vuitton', 'chanel', 'hermes',
    'leather handbag', 'luxury handbag', 'designer bag', 'precious metal', 'diamond', 'jewelry',
    'sports car', 'yacht', 'caviar', 'perfume', 'high-end watch', 'fur coat', 'champagne'
]

# General Utility / Non-Luxury Allowance Keywords
GENERAL_UTILITY_KEYWORDS = [
    'canvas bag', 'jute bag', 'cotton bag', 'carry bag', 'shopping bag', 'tote bag',
    'utility bag', 'agricultural sack', 'rice bag', 'cashew', 'cotton', 'foodstuff',
    'grain', 'wheat', 'pharmaceutical', 'medical supplies', 'edible'
]

# Dual-Use / Military / EAR99 Prohibited Keywords
DUAL_USE_KEYWORDS = [
    'military', 'tactical', 'weapon', 'nuclear', 'dual-use', 'ballistic',
    'high-spec computing', 'surveillance grade', 'optics', 'night vision',
    'drone', 'uav', 'missile', 'centrifuge', 'encryption module', 'radar', 'arms', 'ammunition'
]


def check_trade_route_sanctions(destination_country: str, origin_country: str = None, port_of_discharge: str = None, port_of_loading: str = None) -> dict:
    """
    Screens trade route (destination country, ports, origin) against embargoed jurisdictions and high-risk hubs.
    """
    dest_str = f"{destination_country or ''} {port_of_discharge or ''}".upper()
    pol_str = f"{origin_country or ''} {port_of_loading or ''}".upper()

    matched_jurisdiction = None
    for key, info in SANCTIONED_JURISDICTIONS.items():
        if re.search(r'\b' + re.escape(key) + r'\b', dest_str) or re.search(r'\b' + re.escape(key) + r'\b', pol_str):
            matched_jurisdiction = info
            break

    matched_hub = None
    for hub, hub_info in HIGH_RISK_HUBS.items():
        if hub in dest_str or hub in pol_str:
            matched_hub = (hub, hub_info)
            break

    if matched_jurisdiction:
        risk_lvl = 'RED_FLAG' if matched_jurisdiction['risk'] == 'EMBARGOED' else 'REVIEW_REQUIRED'
        return {
            'sanctioned': True,
            'jurisdiction': matched_jurisdiction['name'],
            'country_code': matched_jurisdiction['code'],
            'risk_level': risk_lvl,
            'details': f"Destination/Transit jurisdiction '{matched_jurisdiction['name']}' is subject to {matched_jurisdiction['description']}."
        }

    if matched_hub:
        hub_name, hub_data = matched_hub
        return {
            'sanctioned': True,
            'jurisdiction': f"{hub_name} ({hub_data['country']})",
            'country_code': None,
            'risk_level': 'RED_FLAG' if hub_data['risk'] == 'EMBARGOED_PORT' else 'REVIEW_REQUIRED',
            'details': f"High-risk transshipment port flagged: '{hub_name}' in {hub_data['country']} ({hub_data['risk']})."
        }

    return {
        'sanctioned': False,
        'jurisdiction': destination_country or 'Unrestricted Jurisdiction',
        'country_code': None,
        'risk_level': 'CLEAR',
        'details': f"Destination jurisdiction '{destination_country or 'Declared Destination'}' is clear of comprehensive trade embargoes."
    }


def evaluate_restricted_goods(product_description: str, hs_code: str = None, destination_country: str = None) -> dict:
    """
    Evaluates commodity description and HS Chapter codes against dual-use & luxury goods restriction lists.
    HS Code Chapter checks:
    - Chapter 93 (Arms/Ammunition): RED_FLAG
    - Chapter 88 (Aircraft/Spacecraft): RED_FLAG (without export license)
    - Chapter 71 (Precious Metals/Diamonds): LUXURY
    - Chapter 91 (Clocks/Watches): LUXURY check
    """
    desc_lower = (product_description or '').lower()
    dest_upper = (destination_country or '').upper()

    hs_chapter = None
    if hs_code:
        clean_hs = re.sub(r'[^0-9]', '', str(hs_code))
        if len(clean_hs) >= 2:
            hs_chapter = clean_hs[:2]

    # Check HS Chapter specific rules
    if hs_chapter == '93':
        return {
            'is_restricted': True,
            'category': 'ARMS_AND_AMMUNITION',
            'flag': 'RED_FLAG',
            'matched_keywords': ['HS Chapter 93 (Arms & Ammunition)'],
            'reason': 'RED FLAG: HS Chapter 93 classified as Arms & Ammunition. Mandatory military export control license required.'
        }

    # Check Dual-Use / Military Keywords
    matched_dual_use = [kw for kw in DUAL_USE_KEYWORDS if kw in desc_lower]
    if matched_dual_use:
        return {
            'is_restricted': True,
            'category': 'DUAL_USE',
            'flag': 'RED_FLAG',
            'matched_keywords': matched_dual_use,
            'reason': f"RED FLAG: Dual-use / military restriction triggered for keyword(s): {', '.join(matched_dual_use)}. EAR99/ITAR export authorization required."
        }

    # Check Destination Specific Rules (e.g. North Korea / KP)
    is_kp = any(k in dest_upper for k in ['KP', 'NORTH KOREA', 'DPRK'])

    if is_kp:
        matched_luxury = [kw for kw in LUXURY_KEYWORDS if kw in desc_lower]
        matched_utility = [kw for kw in GENERAL_UTILITY_KEYWORDS if kw in desc_lower]

        if matched_luxury or hs_chapter in ['71', '91']:
            return {
                'is_restricted': True,
                'category': 'LUXURY_GOODS',
                'flag': 'RED_FLAG',
                'matched_keywords': matched_luxury or [f'HS Chapter {hs_chapter}'],
                'reason': f"RED FLAG: Luxury goods restriction triggered for '{product_description}': Strictly prohibited under UN SCR 2270 & OFAC sanctions for destination KP."
            }

        if matched_utility or any(w in desc_lower for w in ['bag', 'cotton', 'jute', 'canvas', 'cashew', 'rice', 'food']):
            return {
                'is_restricted': False,
                'category': 'GENERAL_MERCHANDISE',
                'flag': 'REVIEW_REQUIRED',
                'matched_keywords': matched_utility or ['utility goods'],
                'reason': f"ALLOWED (WITH REVIEW): General utility merchandise ('{product_description}') permitted under standard clearance for destination KP."
            }

        return {
            'is_restricted': True,
            'category': 'EMBARGOED_COMMODITY',
            'flag': 'REVIEW_REQUIRED',
            'matched_keywords': [],
            'reason': f"REVIEW REQUIRED: Commodity '{product_description}' bound for high-risk jurisdiction KP requires end-user verification."
        }

    # Standard Unrestricted Route Screening
    matched_luxury = [kw for kw in LUXURY_KEYWORDS if kw in desc_lower]
    if matched_luxury:
        return {
            'is_restricted': False,
            'category': 'LUXURY_GOODS',
            'flag': 'CLEAR',
            'matched_keywords': matched_luxury,
            'reason': f"Commercial luxury goods ('{product_description}') declared for unrestricted destination."
        }

    return {
        'is_restricted': False,
        'category': 'GENERAL_MERCHANDISE',
        'flag': 'CLEAR',
        'matched_keywords': [],
        'reason': f"General commercial merchandise ('{product_description}') cleared for standard export."
    }


def screen_trade_route(data: dict) -> dict:
    """
    Evaluates complete trade route parameters:
    - Embargoed country screening
    - Port UN/LOCODE verification
    - Dual-use & luxury goods classification
    - AIS nautical transit feasibility (18-22 knots)
    """
    pol = data.get('port_of_loading') or data.get('origin_country') or 'India'
    pod = data.get('port_of_discharge') or data.get('destination_country') or 'USA'
    dest_country = data.get('destination_country') or pod
    origin_country = data.get('country_of_origin') or data.get('origin_country') or pol
    prod_desc = data.get('product_description') or 'General Commercial Cargo'
    hs_code = data.get('hs_code')
    vessel = data.get('vessel_name')
    ship_date = data.get('shipped_on_board_date')

    # 1. Route screening
    route_res = check_trade_route_sanctions(dest_country, origin_country=origin_country, port_of_discharge=pod, port_of_loading=pol)

    # 2. Goods screening
    goods_res = evaluate_restricted_goods(prod_desc, hs_code=hs_code, destination_country=dest_country)

    # 3. AIS Telemetry & Voyage Feasibility
    ais_res = validate_voyage_feasibility(pol, pod, shipment_date=ship_date)

    status = 'CLEAR'
    if route_res['risk_level'] == 'RED_FLAG' or goods_res['flag'] == 'RED_FLAG':
        status = 'RED_FLAG'
    elif route_res['risk_level'] == 'REVIEW_REQUIRED' or goods_res['flag'] == 'REVIEW_REQUIRED' or ais_res.get('status') == 'ANOMALY':
        status = 'REVIEW_REQUIRED'

    return {
        'status': status,
        'route_screening': route_res,
        'goods_screening': goods_res,
        'ais_feasibility': ais_res,
        'summary': f"Sanctions verdict: {status}. Destination: {dest_country}. Commodity: {goods_res['category']}."
    }


def run_frm_screening(extracted_fields: dict, customer_context: dict = None) -> dict:
    """
    Orchestrates FRM (Fraud & Risk Management) and Trade Route Sanctions Screening for multi-doc packages.
    """
    customer_name = (customer_context or {}).get('exporter', 'Nutri Max')

    destination_country = None
    origin_country = None
    port_of_discharge = None
    port_of_loading = None
    product_descriptions = []
    hs_codes = []
    vessel_name = None
    ship_date = None

    if isinstance(extracted_fields, dict):
        for doc_type, doc_data in extracted_fields.items():
            if not isinstance(doc_data, dict):
                continue
            fields = doc_data.get('fields', {})

            def gv(k):
                val = fields.get(k)
                if isinstance(val, dict):
                    return val.get('value')
                return val

            dest = gv('destination_country')
            orig = gv('country_of_origin')
            pod  = gv('port_of_discharge')
            pol  = gv('port_of_loading')
            prod = gv('product_description')
            hs   = gv('hs_code')
            vsl  = gv('vessel_name')
            s_dt = gv('shipped_on_board_date')

            if dest and not destination_country: destination_country = dest
            if orig and not origin_country: origin_country = orig
            if pod and not port_of_discharge: port_of_discharge = pod
            if pol and not port_of_loading: port_of_loading = pol
            if prod and prod not in product_descriptions: product_descriptions.append(prod)
            if hs and hs not in hs_codes: hs_codes.append(hs)
            if vsl and not vessel_name: vessel_name = vsl
            if s_dt and not ship_date: ship_date = s_dt

    combined_product_desc = ' '.join(product_descriptions) if product_descriptions else 'General Cargo'
    combined_hs = ', '.join(hs_codes) if hs_codes else None

    route_data = {
        'port_of_loading': port_of_loading or 'Nhava Sheva',
        'port_of_discharge': port_of_discharge or destination_country or 'Los Angeles',
        'destination_country': destination_country or 'USA',
        'origin_country': origin_country or 'India',
        'product_description': combined_product_desc,
        'hs_code': combined_hs,
        'vessel_name': vessel_name,
        'shipped_on_board_date': ship_date
    }

    screen_res = screen_trade_route(route_data)

    return {
        'status': screen_res['status'],
        'summary': screen_res['summary'],
        'destination_country': destination_country or 'Declared',
        'port_of_discharge': port_of_discharge or 'Declared',
        'product_description': combined_product_desc,
        'route_screening': screen_res['route_screening'],
        'goods_screening': screen_res['goods_screening'],
        'ais_feasibility': screen_res['ais_feasibility'],
        'customer': customer_name,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }


# ─────────────────────────────────────────────────────────────
# 5. UNIVERSAL HS-BASED COMPLIANCE & VALUE-THRESHOLD ENGINE
# ─────────────────────────────────────────────────────────────

# Universal international sanctions & export control policy matrix
GLOBAL_TRADE_POLICIES = [
    {
        "policy_id": "SANCTION-LUX-EU-001",
        "authority": "EU Council Regulation (Sanctions Regime) / US EAR",
        "description": "Statutory threshold for luxury consumer goods",
        "target_jurisdictions": ["RUSSIA", "BELARUS"],
        "action": "CRITICAL_BLOCK",
        "rules": [
            {
                "name": "Luxury Consumer Goods (Apparel, Leather, Footwear, Perfumes)",
                "hs_chapters": ["33", "42", "43", "61", "62", "64", "65"],
                "threshold_type": "UNIT_VALUE",
                "threshold_limit": 300.0,
                "currency": "EUR"
            },
            {
                "name": "Consumer Electronics, Audio/Visual & Home Appliances",
                "hs_chapters": ["84", "85"],
                "threshold_type": "UNIT_VALUE",
                "threshold_limit": 750.0,
                "currency": "EUR"
            },
            {
                "name": "Jewelry, Precious Metals & Timepieces",
                "hs_chapters": ["71", "91"],
                "threshold_type": "UNIT_VALUE",
                "threshold_limit": 300.0,
                "currency": "EUR"
            },
            {
                "name": "Luxury Vehicles & High-End Transport",
                "hs_chapters": ["87", "88", "89"],
                "threshold_type": "CONSIGNMENT_VALUE",
                "threshold_limit": 50000.0,
                "currency": "EUR"
            }
        ]
    },
    {
        "policy_id": "SANCTION-TOTAL-EMBARGO-002",
        "authority": "UN Security Council / OFAC Comprehensive Sanctions",
        "description": "Comprehensive territorial embargo on designated countries",
        "target_jurisdictions": ["NORTH KOREA", "IRAN", "SYRIA", "CUBA"],
        "action": "CRITICAL_BLOCK",
        "rules": [
            {
                "name": "All Commercial Cargo (Chapters 01 through 99)",
                "hs_chapters": ["*"],
                "threshold_type": "TOTAL_BAN",
                "threshold_limit": 0.0,
                "currency": "USD"
            }
        ]
    },
    {
        "policy_id": "DUAL-USE-EXPORT-CONTROL-003",
        "authority": "Wassenaar Arrangement / US BIS Commerce Control List",
        "description": "Strategic dual-use & high-technology screening",
        "target_jurisdictions": ["RUSSIA", "BELARUS", "CHINA", "IRAN", "NORTH KOREA"],
        "action": "EXPORT_LICENSE_REQUIRED",
        "rules": [
            {
                "name": "Strategic Dual-Use Technologies (Chemicals, Microelectronics, Specialized Optics)",
                "hs_chapters": ["28", "84", "85", "90"],
                "threshold_type": "ANY_VALUE",
                "threshold_limit": 0.0,
                "currency": "USD"
            }
        ]
    }
]


class UniversalComplianceEngine:
    def __init__(self, policies: List[Dict[str, Any]] = None):
        self.policies = policies or GLOBAL_TRADE_POLICIES
        self.fx_rates_to_eur = {
            "EUR": 1.0, 
            "USD": 0.92, 
            "GBP": 1.17, 
            "INR": 0.011, 
            "AED": 0.25, 
            "SGD": 0.69
        }
        self.jurisdiction_aliases = {
            "KP": "NORTH KOREA",
            "DPRK": "NORTH KOREA",
            "RU": "RUSSIA",
            "IR": "IRAN",
            "SY": "SYRIA",
            "CU": "CUBA",
            "BY": "BELARUS",
            "CN": "CHINA"
        }

    def _to_eur(self, amount: float, currency: str) -> float:
        rate = self.fx_rates_to_eur.get(currency.upper(), 1.0)
        return amount * rate

    def evaluate_shipment(self, extracted_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Dynamically evaluates ANY shipment parameters against global trade policies.
        """
        violations = []
        destination = str(extracted_data.get("destination_country", "")).strip().upper()
        alias_dest = self.jurisdiction_aliases.get(destination, destination)

        raw_hs = str(extracted_data.get("hs_code", "")).replace(".", "").strip()
        hs_2digit = raw_hs[:2] if len(raw_hs) >= 2 else ""
        
        currency = str(extracted_data.get("currency", "USD")).upper()
        total_amount = float(extracted_data.get("total_amount") or 0.0)
        unit_price = float(extracted_data.get("unit_price") or 0.0)
        quantity = float(extracted_data.get("quantity") or 1.0)

        # Derive unit price if total and quantity exist
        if unit_price == 0.0 and quantity > 0 and total_amount > 0:
            unit_price = total_amount / quantity

        for policy in self.policies:
            target_jurisdictions = [j.upper() for j in policy.get("target_jurisdictions", [])]
            if not any(j in destination or j in alias_dest for j in target_jurisdictions):
                continue

            for rule in policy.get("rules", []):
                rule_chapters = rule.get("hs_chapters", [])
                if "*" not in rule_chapters and (not hs_2digit or hs_2digit not in rule_chapters):
                    continue

                threshold_type = rule.get("threshold_type")
                rule_limit = float(rule.get("threshold_limit", 0.0))
                rule_curr = rule.get("currency", "EUR")

                limit_eur = self._to_eur(rule_limit, rule_curr)
                unit_eur = self._to_eur(unit_price, currency)
                total_eur = self._to_eur(total_amount, currency)

                is_breach = False
                reason = ""

                if threshold_type == "TOTAL_BAN":
                    is_breach = True
                    reason = f"Comprehensive embargo on {destination or alias_dest}. All commercial trade prohibited under OFAC/UN sanctions."
                elif threshold_type == "ANY_VALUE":
                    is_breach = True
                    reason = f"Dual-Use Technology Restriction: HS Chapter {hs_2digit} exported to {destination or alias_dest} requires statutory export license clearance."
                elif threshold_type == "UNIT_VALUE" and unit_eur > limit_eur:
                    is_breach = True
                    reason = (f"Declared unit value ({currency} {unit_price:,.2f} ≈ €{unit_eur:,.2f}) "
                              f"exceeds statutory luxury limit of {rule_curr} {rule_limit:,.2f} for {rule.get('name')}.")
                elif threshold_type == "CONSIGNMENT_VALUE" and total_eur > limit_eur:
                    is_breach = True
                    reason = (f"Consignment total ({currency} {total_amount:,.2f} ≈ €{total_eur:,.2f}) "
                              f"exceeds permissible threshold of {rule_curr} {rule_limit:,.2f} for {destination or alias_dest}.")

                if is_breach:
                    violations.append({
                        "policy_id": policy.get("policy_id"),
                        "authority": policy.get("authority"),
                        "severity": policy.get("action", "CRITICAL_BLOCK"),
                        "category": rule.get("name"),
                        "reason": reason,
                        "hs_chapter": hs_2digit
                    })

        return violations


# Global singleton instance
compliance_evaluator = UniversalComplianceEngine()

