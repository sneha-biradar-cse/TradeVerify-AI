# v35b - presentation fixes on top of v35

1. **Login code no longer shown on screen.** `start.bat` / `start.sh` now set `SHOW_DEV_HINTS=0`. The page shows no code and
   no "(demo)" word, the demo-account footer is hidden, and the code is not in the network response either.
   Without email the code appears only in the server window (the PowerShell/terminal that runs the server).
   For a realistic demo, set the SMTP lines in `start.bat` (see the comments there) so the code arrives by real email.
   Set `SHOW_DEV_HINTS=1` to get the old developer behaviour back.
2. **Admin page: one bar per block.** One incident freezes the account, the card and the browser session; they were shown as
   3 bars with the same reference. Now there is one bar with a "Blocked: ..." line, and one Unblock clears everything and
   writes ONE line in the admin history. "Clear All" works per incident too.
3. **Admin page: explanations.** Hover any "Last 24 hours" tile for its meaning, and open "What do these terms mean?".
4. The "Receivables" (exporter) / "Pay Invoice" (importer) split was already in v35 and is unchanged.

Files changed: security.py, auth_engine.py, account_unlock.py, server.py, admin.html, exporter-login.html, importer-login.html,
start.bat, start.sh, .env.example. New: logs/test_presentation_fixes.py (12 checks). All older v35 tests still pass.
