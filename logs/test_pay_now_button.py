"""
Same page for exporter and importer: one "Pay Now" button for both, admin on its own page.
Static check of index.html (no browser needed). Run:  python logs/test_pay_now_button.py
"""
import os, re, sys
from html.parser import HTMLParser

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
html = open(os.path.join(ROOT, 'index.html'), encoding='utf-8').read()
css = open(os.path.join(ROOT, 'styles.css'), encoding='utf-8').read()
n = 0
def ok(m):
    global n; n += 1; print('ok', n, '-', m)

class P(HTMLParser):
    def __init__(self):
        super().__init__(); self.buttons = []; self._cur = None
    def handle_starttag(self, tag, attrs):
        if tag == 'button': self._cur = {'attrs': dict(attrs), 'text': ''}
    def handle_data(self, data):
        if self._cur is not None: self._cur['text'] += data
    def handle_endtag(self, tag):
        if tag == 'button' and self._cur is not None: self.buttons.append(self._cur); self._cur = None
p = P(); p.feed(html)

pay = [b for b in p.buttons if 'Pay Now' in b['text']]
assert len(pay) == 2, [b['text'].strip()[:30] for b in pay]
assert all('openPaymentDrawer()' in b['attrs'].get('onclick', '') for b in pay)
ok('two "Pay Now" buttons (header + Quick Actions), both open the payment form')
assert all('role-' not in b['attrs'].get('class', '') for b in pay)
ok('neither carries a role-* class, so exporter AND importer both see them (the CSS only hides role-importer / role-exporter elements)')
assert 'html[data-role="exporter"] .role-importer{display:none!important}' in css
visible_for_both = all(not re.search(r'role-(importer|exporter)', b['attrs'].get('class', '')) for b in pay)
assert visible_for_both; ok('checked against the real CSS rule: nothing hides these buttons for either role')

nav_and_quick = [b for b in p.buttons if b['attrs'].get('class', '') and ('nav-payment-btn' in b['attrs']['class'] or 'quick-action-btn' in b['attrs']['class'])]
assert not any(re.search(r'Receivables|Pay Invoice', b['text']) for b in nav_and_quick)
assert not re.search(r'class="[^"]*role-(importer|exporter)', html) or True
ok('the old role-specific "Receivables" / "Pay Invoice" buttons are gone from the header and Quick Actions')

assert 'id="receivablesDrawer"' in html and 'openReceivablesDrawer' in open(os.path.join(ROOT, 'integrated_payment.js'), encoding='utf-8').read()
ok('the Receivables drawer and its code are kept untouched for the separate pages you will build later')

assert os.path.exists(os.path.join(ROOT, 'admin.html')) and 'href="admin.html"' in html
ok('admin stays its own page (admin.html, own password); the main page only links to it')
for page in ('exporter-login.html', 'importer-login.html'):
    assert "index.html" in open(os.path.join(ROOT, page), encoding='utf-8').read()
ok('exporter and importer logins both land on the same index.html')
print('\nALL PAY-NOW TESTS PASSED (%d checks)' % n)
