@echo off
cd /d "%~dp0"
if exist payment_ledger.json del payment_ledger.json
echo Test invoice reset. Now run start.bat
pause
