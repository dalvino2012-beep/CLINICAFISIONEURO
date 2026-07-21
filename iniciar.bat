@echo off
cd /d "%~dp0"
echo Iniciando FISIONEURO - Sistema de Clinica Medica...
echo Acesse http://localhost:3001 no navegador.
echo.
".\venv\Scripts\python.exe" app.py
pause
