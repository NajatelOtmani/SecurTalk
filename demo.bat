@echo off
REM Lance backend + service IA (le VRAI s'il existe dans ml\, sinon le faux) + 2 clients.
REM A placer a la racine du depot (dossier securetalk).
cd /d "%~dp0"
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8000,8001 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"
timeout /t 2 /nobreak >nul
start "Backend" cmd /k "cd /d %~dp0backend && python -m uvicorn app.main:app --port 8000"
if exist "%~dp0ml\service\main.py" (
  start "IA (vrai)" cmd /k "cd /d %~dp0ml && python -m uvicorn service.main:app --host 127.0.0.1 --port 8001"
) else (
  start "IA (faux)" cmd /k "cd /d %~dp0client && python tools\fake_ml_service.py"
)
timeout /t 5 /nobreak >nul
start "Client Alice" cmd /k "cd /d %~dp0client && python app.py --profile alice"
start "Client Bob" cmd /k "cd /d %~dp0client && python app.py --profile bob"
