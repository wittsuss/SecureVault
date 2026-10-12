@echo off
title SecureVault
cd /d "%~dp0"
echo.
echo   Iniciando SecureVault...
echo   No cierres esta ventana mientras uses el programa.
echo.
runtime\node.exe app\server.js
echo.
echo   SecureVault se detuvo. Puedes cerrar esta ventana.
pause >nul
