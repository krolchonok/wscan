@echo off
setlocal
cd /d "%~dp0"
if not exist "%~dp0wscan.exe" (
    echo wscan.exe is missing. Extract the complete release ZIP first.
    exit /b 1
)
"%~dp0wscan.exe" %*
exit /b %ERRORLEVEL%
