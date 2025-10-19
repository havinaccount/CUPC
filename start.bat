@echo off
setlocal enabledelayedexpansion

:: Move to the directory of this script
cd /d "%~dp0"

:: Log file setup
set "LOGFILE=%~dp0cupc_log.txt"
echo [%date% %time%] Starting CUPC >> "%LOGFILE%"

:: Prompt user for choice
echo Choose which file to run:
echo 1 - CUPC.exe
echo 2 - CUPC.py
set /p choice="Enter 1 or 2: "

:: Initialize exit code
set "EXITCODE=-1"

if "%choice%"=="1" (
    :: Check if CUPC.exe exists
    if exist "CUPC.exe" (
        echo [%date% %time%] Executing CUPC.exe... >> "%LOGFILE%"
        start /wait "" "CUPC.exe"
        set "EXITCODE=%ERRORLEVEL%"
    ) else (
        echo [%date% %time%] ERROR: CUPC.exe not found in %~dp0 >> "%LOGFILE%"
        echo ERROR: CUPC.exe not found. Make sure it's in the same folder as this script.
        goto end
    )
) else if "%choice%"=="2" (
    :: Check if CUPC.py exists
    if exist "CUPC.py" (
        echo [%date% %time%] Executing CUPC.py... >> "%LOGFILE%"
        python "CUPC.py"
        set "EXITCODE=%ERRORLEVEL%"
    ) else (
        echo [%date% %time%] ERROR: CUPC.py not found in %~dp0 >> "%LOGFILE%"
        echo ERROR: CUPC.py not found. Make sure it's in the same folder as this script.
        goto end
    )
) else (
    echo [%date% %time%] ERROR: Invalid choice entered. >> "%LOGFILE%"
    echo Invalid choice. Please run the script again and enter 1 or 2.
    goto end
)

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
