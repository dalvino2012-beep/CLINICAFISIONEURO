@echo off
title FISIONEURO - SERVIDOR LIGADO (NAO FECHE ESTA JANELA - so minimize)
cd /d "%~dp0"
echo ============================================================
echo   FISIONEURO - Sistema da Clinica Medica
echo ============================================================
echo.
echo   O SISTEMA ESTA LIGADO enquanto esta janela estiver aberta.
echo   NAO FECHE esta janela - apenas MINIMIZE (botao _ no canto).
echo.
echo   Acesse no navegador:  http://localhost:3001
echo.
echo ============================================================
echo.
".\venv\Scripts\python.exe" app.py
echo.
echo   O servidor parou. Feche esta janela e abra o atalho de novo.
pause
