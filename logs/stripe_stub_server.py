# Stand-in for Stripe (for checking the Stripe-mode wiring WITHOUT Stripe keys or internet). Run from the project folder:
#   set PAYMENT_PROVIDER_MODE=stripe, ENVIRONMENT=development, STRIPE_SECRET_KEY=sk_test_stub, then: python logs/stripe_stub_server.py
# It replaces the Stripe gateway functions BEFORE server.py imports them, then runs the real server. NOT a real Stripe test.
import sys, time, runpy, itertools
sys.path.insert(0, '.')
import stripe_payment_gateway as G
import account_scout as S
class Obj(dict):
    __getattr__ = dict.get
STORE = {}; N = itertools.count(1)
def create(amount_minor, currency, invoice_ref, account_id, session_id, idem):
    pid = f'pi_stub_{next(N)}'
    STORE[pid] = Obj(id=pid, client_secret=pid+'_secret', status='requires_payment_method',
                     metadata={'tradeverify_account_id': account_id, 'tradeverify_invoice_ref': invoice_ref})
    return STORE[pid]
G.create_payment_intent = create
G.retrieve_payment_intent = lambda pid: STORE[pid]
G.retrieve_payment_method = lambda pm: (Obj(id=pm), 'fp_' + pm)
def attach(pid, pm, decision, score): STORE[pid]['metadata']['tradeverify_fraud_decision'] = decision
G.attach_payment_method = attach
G.cancel_payment_intent = lambda pid, reason='': None
G.publishable_key = lambda: 'pk_test_stub'
now = time.time()
for _ in range(3): S._STORE.sliding_count('failed:account:exporter:gateuser', now, 600)   # 3 declines already on this account
runpy.run_path('server.py', run_name='__main__')
