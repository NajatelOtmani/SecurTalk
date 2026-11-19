@echo off
REM 1) tests automatiques de tous les dossiers  2) verification du systeme REEL (demo.bat doit etre lance)
cd /d "%~dp0client"
echo ===== TESTS AUTOMATIQUES (crypto_sdk, backend, ml, soc, client) =====
python tools\run_all_tests.py
echo.
echo ===== VERIFICATION DU SYSTEME REEL (backend et IA doivent tourner) =====
python tools\system_check.py
pause
