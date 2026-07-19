@echo off
REM Stops both Network Guardian server windows started by start.bat

echo Stopping Network Guardian...

taskkill /FI "WINDOWTITLE eq Network Guardian - API*" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq Network Guardian - Dashboard*" /T /F >nul 2>&1

echo Stopped. (If a window is still open, you can also just close it manually.)
pause
