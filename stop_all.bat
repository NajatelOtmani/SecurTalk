@echo off
REM Libere les ports 8000 (backend), 8001 (IA) et 8002 (SOC) si un ancien processus les occupe.
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8000,8001,8002 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"
echo Ports 8000, 8001 et 8002 liberes.
if not "%1"=="silent" pause
