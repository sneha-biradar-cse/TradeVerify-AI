"""Small file-backed payment ledger for local Stripe test mode.

For production this should be replaced by the client's transactional database.
The ledger is deliberately separate from the Stripe provider adapter so the
provider remains the source of payment truth and the webhook updates local UI
state.
"""
import json, os, tempfile, threading

_LOCK = threading.Lock()

def _path():
    return os.environ.get('PAYMENT_LEDGER_FILE', 'payment_ledger.json').strip() or 'payment_ledger.json'

def _read():
    try:
        with open(_path(), 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {}
    except Exception:
        return {}

def _write(data):
    path = _path()
    directory = os.path.dirname(os.path.abspath(path)) or '.'
    fd, tmp = tempfile.mkstemp(prefix='.payment-ledger-', suffix='.tmp', dir=directory, text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def record_payment(invoice_ref, payment_intent_id, status, account_id=''):
    with _LOCK:
        data = _read()
        data[invoice_ref] = {
            'payment_intent_id': payment_intent_id,
            'status': status,
            'account_id': account_id,
        }
        _write(data)

def get_payment(invoice_ref):
    with _LOCK:
        return _read().get(invoice_ref)


def clear_all():
    """Development/test helper: mark every invoice unpaid again."""
    with _LOCK:
        _write({})
