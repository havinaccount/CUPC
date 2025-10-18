@echo off
setlocal enabledelayedexpansion

:: Move to the directory of this script
cd /d "%~dp0"

:: Log file setup
set "LOGFILE=%~dp0cupc_log.txt"
echo [%date% %time%] Starting CUPC >> "%LOGFILE%"

:: Check if executable exists
if not exist "CUPC.exe" (
    echo [%date% %time%] ERROR: CUPC.exe not found in %~dp0 >> "%LOGFILE%"
    echo ERROR: CUPC.exe not found. Make sure it's in the same folder as this script.
    goto end
)

:: Run the executable and capture exit code
echo [%date% %time%] Executing CUPC.exe... >> "%LOGFILE%"
start /wait "" "CUPC.exe"
set "EXITCODE=%ERRORLEVEL%"

:: Log result
if "!EXITCODE!"=="0" (
    echo [%date% %time%] CUPC executed successfully. >> "%LOGFILE%"
) else (
    echo [%date% %time%] ERROR: CUPC exited with code !EXITCODE! >> "%LOGFILE%"
    echo ERROR: CUPC failed with exit code !EXITCODE!
)

:end
echo [%date% %time%] Script finished. >> "%LOGFILE%"
pause
endlocal
