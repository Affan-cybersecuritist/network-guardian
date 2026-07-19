@echo off
REM One-command startup for Network Guardian on Windows.
REM Just double-click this file, or run it from Command Prompt: start.bat

cd /d "%~dp0"

echo Checking dependencies (this may take a minute the first time)...
pip install -q pandas numpy scikit-learn joblib fastapi uvicorn websockets python-multipart scapy requests

if not exist "models\isolation_forest.joblib" (
    echo No trained model found - training now, one-time, about 30 seconds...
    python notebooks\train_model.py
) else (
    echo Trained model found, skipping training.
)

echo Starting backend API on port 8000...
start "Network Guardian - API (keep this window open)" cmd /k "python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000"

timeout /t 3 /nobreak >nul

echo Starting dashboard on port 8080...
cd frontend
start "Network Guardian - Dashboard (keep this window open)" cmd /k "python -m http.server 8080"
cd ..

timeout /t 2 /nobreak >nul

echo.
echo ==========================================
echo   Network Guardian is running!
echo   Opening your browser now...
echo ==========================================
echo.
echo Two new windows just opened - LEAVE THEM OPEN.
echo Closing them stops the servers.
echo To stop everything, just close both new windows.
echo.

start http://localhost:8080

pause
