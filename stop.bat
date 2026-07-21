@echo off
REM Stops the Network Guardian server window started by start.bat

echo Stopping Network Guardian...

taskkill /FI "WINDOWTITLE eq Network Guardian*" /T /F >nul 2>&1

REM Also kill any lingering Python process on port 8000
for /f "tokens=5" %%a in ('netstat -ano ^| find "8000" ^| find "LISTENING"') do (
    taskkill /PID %%a /F >nul 2>&1
)

echo Stopped. (If a window is still open, you can also just close it manually.)
pause
