@echo off
setlocal
cd /d "%~dp0"

set "TARGET=d3d9"
if not "%~1"=="" set "TARGET=%~1"

if /i "%TARGET%"=="version" (
    set "OUTPUT=version.dll"
    set "DEF=src\version.def"
) else (
    set "OUTPUT=d3d9.dll"
    set "DEF=src\d3d9.def"
)

echo Building %OUTPUT% (32-bit)...
gcc -m32 -shared -O2 -Wall "src\utf8_hook.c" "%DEF%" -o "%OUTPUT%" -lgdi32 -luser32 -lkernel32 -lshell32

if %ERRORLEVEL% EQU 0 (
    echo Build succeeded: %OUTPUT%
) else (
    echo Build failed with error %ERRORLEVEL%
)
endlocal
