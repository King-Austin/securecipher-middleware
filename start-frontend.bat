@echo off
title SecureCipher Banking Development Environment
color 0A
echo.
echo ================================
echo  SecureCipher Banking Platform
echo ================================
echo.

REM Set Node.js memory limit for Windows
set NODE_OPTIONS=--max-old-space-size=4096

REM Navigate to frontend directory
cd /d "c:\Users\kingaustin\Documents\securecipher_ui"

echo [INFO] Installing cross-env for Windows compatibility...
npm install cross-env --save-dev

echo [INFO] Clearing Vite cache...
npm run build -- --mode development --clearScreen false 2>nul

echo [INFO] Starting React Frontend on port 3000 with Windows optimizations...
echo [INFO] This configuration is optimized for Windows file watching...
echo.

REM Start the React frontend with Windows-specific configuration
npm run dev-windows

echo.
echo Press any key to exit...
pause >nul
