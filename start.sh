#!/bin/sh

# Get absolute script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Log file setup
LOGFILE="$SCRIPT_DIR/cupc_log.txt"
echo "$(date '+[%Y-%m-%d %H:%M:%S]') Starting CUPC" >> "$LOGFILE"

# Prompt user for choice
echo "Choose which file to run:"
echo "1 - CUPC.exe"
echo "2 - CUPC.py"
printf "Enter 1 or 2: "
read choice

if [ -z "$choice" ]; then
    echo "No choice entered. Exiting."
    exit 1
fi

EXITCODE=-1

if [ "$choice" = "1" ]; then
    if [ -f "CUPC.exe" ]; then
        echo "$(date '+[%Y-%m-%d %H:%M:%S]') Executing CUPC.exe..." >> "$LOGFILE"
        wine CUPC.exe   # use wine if it's a Windows binary
        EXITCODE=$?
    else
        echo "$(date '+[%Y-%m-%d %H:%M:%S]') ERROR: CUPC.exe not found in $SCRIPT_DIR" >> "$LOGFILE"
        echo "ERROR: CUPC.exe not found. Make sure it's in the same folder as this script."
        exit 1
    fi
elif [ "$choice" = "2" ]; then
    if [ -f "CUPC.py" ]; then
        echo "$(date '+[%Y-%m-%d %H:%M:%S]') Executing CUPC.py..." >> "$LOGFILE"
        python3 CUPC.py   # safer than python3.13
        EXITCODE=$?
    else
        echo "$(date '+[%Y-%m-%d %H:%M:%S]') ERROR: CUPC.py not found in $SCRIPT_DIR" >> "$LOGFILE"
        echo "ERROR: CUPC.py not found. Make sure it's in the same folder as this script."
        exit 1
    fi
else
    echo "$(date '+[%Y-%m-%d %H:%M:%S]') ERROR: Invalid choice entered." >> "$LOGFILE"
    echo "Invalid choice. Please run the script again and enter 1 or 2."
    exit 1
fi

# Log result
if [ "$EXITCODE" -eq 0 ]; then
    echo "$(date '+[%Y-%m-%d %H:%M:%S]') CUPC executed successfully." >> "$LOGFILE"
else
    echo "$(date '+[%Y-%m-%d %H:%M:%S]') ERROR: CUPC exited with code $EXITCODE" >> "$LOGFILE"
    echo "ERROR: CUPC failed with exit code $EXITCODE"
fi

echo "$(date '+[%Y-%m-%d %H:%M:%S]') Script finished." >> "$LOGFILE"
read -p "Press Enter to continue..."
