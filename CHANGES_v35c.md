# v35c - one page for exporter and importer, "Pay Now" for both

* `index.html`: the role-specific buttons (importer: "Pay Invoice", exporter: "Receivables") are replaced by ONE "Pay Now"
  button in the header and ONE in Quick Actions. Both roles see the same buttons and the same payment form.
* The Receivables drawer and its code are untouched (just not linked yet), ready for the separate pages you will build later.
* Admin is unchanged: its own page (`admin.html`) with its own password. The main page only links to it.
* Everything from v35b is included (login code hidden in presentation mode, one bar per block in admin, glossary).
* New test: `logs/test_pay_now_button.py` (7 checks).
