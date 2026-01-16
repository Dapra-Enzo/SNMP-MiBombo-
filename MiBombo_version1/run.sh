#!/bin/bash
# MiBombo Launcher - Auto-activate venv and run application
# Usage: sudo ./run.sh

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "[ERROR] Please run as root (sudo)"
  echo "Usage: sudo ./run.sh"
  exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "[!] Virtual environment not found!"
    echo "[i] Please run: python3 -m venv venv && ./venv/bin/pip install -r requirements.txt"
    exit 1
fi

# Activate venv and run with -B flag (no bytecode cache)

echo "[+] Launching MiBombo Station..."

# Use absolute path to python in venv to avoid PATH issues with sudo
PYTHON_EXEC="$SCRIPT_DIR/venv/bin/python"

if [ ! -x "$PYTHON_EXEC" ]; then
    echo "[!] Error: Python executable not found at $PYTHON_EXEC"
    exit 1
fi

"$PYTHON_EXEC" -B main.py "$@"
