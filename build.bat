@echo off
setlocal
cd /d "%~dp0"

echo Building version.dll (32-bit)...
gcc -m32 -shared -O2 -Wall "src\utf8_hook.c" "src\version.def" -o "version.dll" -lgdi32 -luser32 -lkernel32 -lshell32

if %ERRORLEVEL% EQU 0 (
    echo Build succeeded: version.dll
) else (
    echo Build failed with error %ERRORLEVEL%
)
endlocal
