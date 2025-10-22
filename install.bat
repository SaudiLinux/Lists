@echo off
echo ================================================
echo Cybersecurity Tool Manager - Installation Script
echo Author: SayerLinux (SaudiLinux1@gmail.com)
echo ================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.7 or higher from https://www.python.org
    pause
    exit /b 1
)

echo [INFO] Python detected:
python --version
echo.

REM Upgrade pip
echo [INFO] Upgrading pip...
python -m pip install --upgrade pip

REM Install requirements
echo [INFO] Installing required packages...
pip install -r requirements.txt

REM Check if nmap is installed
where nmap >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [WARNING] nmap is not installed in PATH
    echo Please install nmap from https://nmap.org/download.html
    echo After installation, make sure nmap is in your system PATH
)

echo.
echo ================================================
echo [SUCCESS] Installation completed!
echo ================================================
echo.
echo To run the tool, execute:
echo python cybersecurity_tool_manager.py
echo.
pause