@echo off
setlocal
cd /d "%~dp0"

set "TARGET=d3d9"
if not "%~1"=="" set "TARGET=%~1"

set "SRC_PREFIX="
if exist "src\utf8_hook.c" set "SRC_PREFIX=src\"

if /i "%TARGET%"=="version" (
    set "OUTPUT=version.dll"
    set "DEF=%SRC_PREFIX%version.def"
) else (
    set "OUTPUT=d3d9.dll"
    set "DEF=%SRC_PREFIX%d3d9.def"
)

echo Building %OUTPUT% (32-bit)...
gcc -m32 -shared -O2 -Wall "%SRC_PREFIX%utf8_hook.c" "%DEF%" -o "%OUTPUT%" -lgdi32 -luser32 -lkernel32 -lshell32

if %ERRORLEVEL% EQU 0 (
    echo Build succeeded: %OUTPUT%
) else (
    echo Build failed with error %ERRORLEVEL%
)
endlocal
