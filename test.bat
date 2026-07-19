@echo off
REM One-command test for Network Guardian on Windows.
REM Run this AFTER start.bat is already running (the two other windows should be open).

cd /d "%~dp0"

echo ==================================================
echo   Network Guardian - Quick Test
echo ==================================================
echo.

echo [1/3] Checking the API is reachable...
curl -s -f http://localhost:8000/health >nul 2>&1
if %errorlevel%==0 (
    echo     API is up
) else (
    echo     API is NOT running. Start it first by running start.bat
    pause
    exit /b 1
)

echo.
echo [2/3] Checking model performance numbers...
curl -s http://localhost:8000/metrics

echo.
echo.
echo [3/3] Generating a test capture (normal traffic + a real port scan + a real SYN flood)
echo       and scoring it through the live model...
python notebooks\generate_test_pcap.py
python backend\score_pcap.py

echo.
echo ==================================================
echo   Test complete. If you see mostly ATTACK flags
echo   on the scan/flood rows above and low risk scores
echo   on normal traffic, everything is working.
echo ==================================================
pause
