@echo off
title FG-VAPT Installer — FluentGrid Technology Solutions
color 0A

echo.
echo  =========================================================
echo   FG-VAPT Setup — FluentGrid Technology Solutions
echo  =========================================================
echo.

:: ── Step 1: Check Python ──────────────────────────────────
echo [1/5] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo  ERROR: Python not found!
    echo  Please download and install Python 3.10+ from https://python.org
    echo  Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)
python --version
echo  Python OK.
echo.

:: ── Step 2: Upgrade pip ───────────────────────────────────
echo [2/5] Upgrading pip...
python -m pip install --upgrade pip --quiet
echo  pip upgraded.
echo.

:: ── Step 3: Install Python packages ──────────────────────
echo [3/5] Installing Python packages (flask, gtts, requests, psutil, wafw00f)...
pip install flask gtts requests psutil wafw00f --quiet
if errorlevel 1 (
    echo  WARNING: Some packages may have failed. Try running as Administrator.
) else (
    echo  All Python packages installed successfully.
)
echo.

:: ── Step 4: Install sqlmap (Python-based, works on Windows) ─
echo [4/5] Installing sqlmap...
pip install sqlmap --quiet 2>nul || echo  sqlmap pip install skipped — will try git clone method.
if not exist "tools\sqlmap" (
    where git >nul 2>&1
    if not errorlevel 1 (
        mkdir tools 2>nul
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git tools\sqlmap --quiet
        echo  sqlmap cloned to tools\sqlmap
    ) else (
        echo  git not found. Download sqlmap from https://sqlmap.org and place in tools\sqlmap\
    )
)
echo.

:: ── Step 5: Check nmap ────────────────────────────────────
echo [5/5] Checking nmap...
where nmap >nul 2>&1
if errorlevel 1 (
    echo  nmap NOT found on PATH.
    echo.
    echo  *** ACTION REQUIRED ***
    echo  Download nmap for Windows from: https://nmap.org/download.html
    echo  Install it and make sure nmap.exe is in your PATH.
    echo  Default install path: C:\Program Files (x86)\Nmap\
    echo  After install, add that folder to System Environment Variables -> PATH
    echo.
) else (
    echo  nmap found!
    nmap --version | findstr "Nmap"
)
echo.

:: ── Summary ───────────────────────────────────────────────
echo  =========================================================
echo   Installation Summary
echo  =========================================================
echo.
echo  INSTALLED (Python / pip):
echo    Flask        — Web framework
echo    gTTS         — Voice output
echo    requests     — HTTP client
echo    psutil       — System info
echo    wafw00f      — WAF detection
echo    sqlmap       — SQL injection testing
echo.
echo  REQUIRES WINDOWS INSTALLER:
echo    nmap         — https://nmap.org/download.html
echo.
echo  REQUIRES WSL2 + Kali Linux (for full coverage):
echo    nikto        — sudo apt install nikto
echo    gobuster     — sudo apt install gobuster
echo    dirb         — sudo apt install dirb
echo    whatweb      — sudo apt install whatweb
echo    nuclei       — https://github.com/projectdiscovery/nuclei/releases
echo    enum4linux   — sudo apt install enum4linux
echo    snmpwalk     — sudo apt install snmp
echo.
echo  To start FG-VAPT after installing nmap:
echo    run.bat
echo.
echo  =========================================================
echo.
pause
