@echo off
REM A lancer UNE SEULE FOIS, depuis la racine du depot (dossier securetalk)
cd /d "%~dp0"
python -m pip install --default-timeout=1000 -e crypto_sdk
python -m pip install --default-timeout=1000 -r backend\requirements.txt
python -m pip install --default-timeout=1000 PySide6-Essentials requests websockets
echo.
echo Installation terminee. Lancez maintenant demo.bat
pause
