@echo off
cd /d "%~dp0"
if not exist logs mkdir logs
"%~dp0venv\Scripts\python.exe" "%~dp0app.py" >> "%~dp0logs\server.log" 2>&1
