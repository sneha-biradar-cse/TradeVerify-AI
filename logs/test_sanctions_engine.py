import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sanctions_engine import (
    check_trade_route_sanctions,
    evaluate_restricted_goods,
    run_frm_screening
)

print('=== TEST 1: CLEAN UNRESTRICTED TRADE ROUTE ===')
# India (INNSA) -> USA (USNYC) with Cashew Nuts -> CLEAR
clean_extraction = {
    'invoice': {
        'fields': {
            'destination_country': {'value': 'United States'},
            'port_of_discharge': {'value': 'USNYC'},
            'product_description': {'value': 'Raw Cashew Nuts in Shell'},
            'hs_code': {'value': '080131'}
        }
    }
}
clean_res = run_frm_screening(clean_extraction, customer_context={'exporter': 'Nutri Max'})
print('Clean Route Result:', json.dumps(clean_res, indent=2))
assert clean_res['status'] == 'CLEAR'
assert clean_res['route_screening']['risk_level'] == 'CLEAR'
assert clean_res['goods_screening']['flag'] == 'CLEAR'

print('\n=== TEST 2: SANCTIONED DESTINATION + GENERAL MERCHANDISE (KP + COTTON BAGS) ===')
# Route to North Korea (KP) with "Standard Cotton Canvas Bags" -> REVIEW_REQUIRED
kp_bags_extraction = {
    'invoice': {
        'fields': {
            'destination_country': {'value': 'North Korea (KP)'},
            'port_of_discharge': {'value': 'Nampo'},
            'product_description': {'value': 'Standard Cotton Canvas Carry Bags'},
            'hs_code': {'value': '630520'}
        }
    }
}
kp_bags_res = run_frm_screening(kp_bags_extraction, customer_context={'exporter': 'Nutri Max'})
print('KP General Bags Result:', json.dumps(kp_bags_res, indent=2))
assert kp_bags_res['status'] == 'REVIEW_REQUIRED'
assert kp_bags_res['route_screening']['sanctioned'] == True
assert kp_bags_res['goods_screening']['flag'] == 'REVIEW_REQUIRED'
assert 'ALLOWED' in kp_bags_res['goods_screening']['reason']

print('\n=== TEST 3: SANCTIONED DESTINATION + LUXURY GOODS (KP + LUXURY HANDBAGS) ===')
# Route to North Korea (KP) with "Luxury Designer Leather Bags" -> RED_FLAG
kp_luxury_extraction = {
    'invoice': {
        'fields': {
            'destination_country': {'value': 'North Korea (KP)'},
            'port_of_discharge': {'value': 'Nampo'},
            'product_description': {'value': 'Luxury Designer Leather Handbags'},
            'hs_code': {'value': '420221'}
        }
    }
}
kp_luxury_res = run_frm_screening(kp_luxury_extraction, customer_context={'exporter': 'Nutri Max'})
print('KP Luxury Goods Result:', json.dumps(kp_luxury_res, indent=2))
assert kp_luxury_res['status'] == 'RED_FLAG'
assert kp_luxury_res['goods_screening']['category'] == 'LUXURY_GOODS'
assert kp_luxury_res['goods_screening']['flag'] == 'RED_FLAG'

print('\n=== TEST 4: DUAL-USE / MILITARY RESTRICTED GOODS ===')
# Any destination with "Tactical Grade Night Vision Optics" -> RED_FLAG
dual_use_extraction = {
    'invoice': {
        'fields': {
            'destination_country': {'value': 'Germany'},
            'port_of_discharge': {'value': 'DEHAM'},
            'product_description': {'value': 'Tactical Grade Night Vision Optics Module'},
            'hs_code': {'value': '901380'}
        }
    }
}
dual_use_res = run_frm_screening(dual_use_extraction, customer_context={'exporter': 'Nutri Max'})
print('Dual-Use Goods Result:', json.dumps(dual_use_res, indent=2))
assert dual_use_res['status'] == 'RED_FLAG'
assert dual_use_res['goods_screening']['category'] == 'DUAL_USE'
assert dual_use_res['goods_screening']['flag'] == 'RED_FLAG'

print('\n[SUCCESS] ALL SANCTIONS & FRM SCREENING ENGINE TESTS PASSED SUCCESSFULLY!')
