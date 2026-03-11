@echo off
title VulnScanner - Backend + Frontend
echo ==========================================
echo   VulnScanner - Starting All Services
echo ==========================================
echo.

:: Start Backend
echo [1/2] Starting Backend (port 8000)...
cd /d "%~dp0"
start "VulnScanner Backend" cmd /k "cd /d "%~dp0" && python -m uvicorn main:app --host 127.0.0.1 --port 8000"

:: Wait a moment for backend to start
timeout /t 3 /nobreak >nul

:: Start Frontend
echo [2/2] Starting Frontend (port 3000)...
start "VulnScanner Frontend" cmd /k "cd /d "%~dp0frontend" && npm run dev"

:: Wait and open browser
timeout /t 5 /nobreak >nul
echo.
echo ==========================================
echo   Backend:  http://127.0.0.1:8000
echo   Frontend: http://localhost:3000
echo ==========================================
echo.
echo Opening browser...
start http://localhost:3000
echo.
echo Press any key to STOP all services...
pause >nul

:: Cleanup
taskkill /FI "WINDOWTITLE eq VulnScanner Backend" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq VulnScanner Frontend" /F >nul 2>&1
echo Services stopped.
