@echo off
setlocal
cd /d "%~dp0"

python .\run_nids.py --check-capture
echo.
python .\run_nids.py --list-interfaces

echo.
pause
