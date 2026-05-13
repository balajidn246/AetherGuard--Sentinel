@echo off
echo ================================================
echo   AetherGuard Sentinel - Enterprise SOC Platform
echo ================================================
echo.

REM Start backend
echo [1/2] Starting FastAPI Backend...
start "AetherGuard Backend" cmd /k "cd /d "%~dp0backend" && python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload"

REM Wait 3 seconds for backend to initialize
timeout /t 3 /nobreak > nul

REM Start frontend
echo [2/2] Starting React Frontend...
start "AetherGuard Frontend" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo.
echo ================================================
echo   Platform starting...
echo   Backend:   http://localhost:8000
echo   Frontend:  http://localhost:5173
echo   API Docs:  http://localhost:8000/docs
echo.
echo   Login: admin / aetherguard2024
echo   Login: analyst / sentinel2024
echo ================================================
echo.
pause
