@echo off
REM Change directory to the folder where this batch file is located
cd /d %~dp0

REM Open default browser to local server URL
start http://127.0.0.1:8000

REM Run the FastAPI app with Uvicorn, disable color codes
py -m uvicorn app:app --reload --no-use-colors

pause
