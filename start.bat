@echo off
title VulnScanner - Backend + Frontend
echo ==========================================
echo   VulnScanner - Starting All Services
echo ==========================================
echo.

:: Start Backend
echo [1/2] Starting Backend (port 6969)...
cd /d "%~dp0"
start "VulnScanner Backend" cmd /k "cd /d "%~dp0" && python -m uvicorn main:app --host 127.0.0.1 --port 6969"

:: Wait a moment for backend to start
timeout /t 3 /nobreak >nul

:: Start Frontend
echo [2/2] Starting Frontend (port 4200)...
start "VulnScanner Frontend" cmd /k "cd /d "%~dp0frontend" && npm run dev -- -p 4200"

:: Wait and open browser
timeout /t 5 /nobreak >nul
echo.
echo ==========================================
echo   Backend:  http://127.0.0.1:6969
echo   Frontend: http://localhost:4200
echo ==========================================
echo.
echo Opening browser...
start http://localhost:4200
echo.
echo Press any key to STOP all services...
pause >nul

:: Cleanup
taskkill /FI "WINDOWTITLE eq VulnScanner Backend" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq VulnScanner Frontend" /F >nul 2>&1
echo Services stopped.
