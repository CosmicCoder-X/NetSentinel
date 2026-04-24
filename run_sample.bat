@echo off
setlocal
cd /d "%~dp0"

python .\run_nids.py --input data\sample_flows.jsonl --config configs\detector_config.json --output-dir reports

echo.
pause
