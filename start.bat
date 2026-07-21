@echo off
cd /d "%~dp0"

echo Checking Python...
python --version
if errorlevel 1 (
    echo ERROR: Python not installed or not in PATH
    pause
    exit /b 1
)

echo.
echo Installing dependencies...
pip install -q -r requirements.txt

echo.
echo Training model if needed...
python notebooks/train_model.py >nul 2>&1

echo.
echo Starting Network Guardian on http://localhost:8000 ...
echo.

REM One process serves both the API and the dashboard (backend/main.py mounts
REM frontend/ as static files) -- no separate frontend server needed anymore.
start "Network Guardian" cmd /k python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000

timeout /t 3 /nobreak

echo.
echo Opening dashboard in browser...
start http://localhost:8000

echo.
echo Keep the window open. To stop, close it or run stop.bat
pause
