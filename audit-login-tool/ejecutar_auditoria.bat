@echo off
chcp 65001 >nul
title Auditoria General Audit - User Login

echo ============================================================
echo   Herramienta de analisis General Audit (User Login)
echo ============================================================
echo.
echo Arrastra y suelta los archivos CSV o ZIP sobre este .bat,
echo o escribe las rutas a continuacion.
echo.

if "%~1"=="" (
    echo No se recibieron archivos.
    echo.
    echo Uso:
    echo   1. Arrastra archivos CSV o ZIP sobre este .bat
    echo   2. O ejecuta desde CMD:
    echo      python audit_login.py archivo1.csv archivo2.csv -o salida.xlsx
    echo.
    pause
    exit /b 1
)

REM Construir la lista de archivos recibidos
set "ARCHIVOS="
:loop
if "%~1"=="" goto run
set "ARCHIVOS=%ARCHIVOS% "%~1""
shift
goto loop

:run
echo Procesando archivos...
echo.
python "%~dp0audit_login.py" %ARCHIVOS%

echo.
echo ============================================================
echo   Proceso terminado. Revisa los archivos generados.
echo ============================================================
echo.
pause
