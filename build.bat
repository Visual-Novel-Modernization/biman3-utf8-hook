@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "TARGET=d3d9"
if not "%~1"=="" set "TARGET=%~1"

if /i "%TARGET%"=="clean" (
    if exist "d3d9.dll" del /f /q "d3d9.dll"
    if exist "version.dll" del /f /q "version.dll"
    if exist "test_exp.dll" del /f /q "test_exp.dll"
    if exist "*.exe" del /f /q "*.exe"
    if exist "*.o" del /f /q "*.o"
    echo Cleaned.
    exit /b 0
)

:: Auto-detect 32-bit MinGW GCC (prefers PATH, then MINGW32_ROOT, then system drive paths)
set "CC="
if defined MINGW32_GCC if exist "%MINGW32_GCC%" set "CC=%MINGW32_GCC%"

if not defined CC (
    where gcc.exe >nul 2>&1
    if !ERRORLEVEL! equ 0 set "CC=gcc"
)

if not defined CC if defined MINGW32_ROOT (
    if exist "%MINGW32_ROOT%\bin\gcc.exe" set "CC=%MINGW32_ROOT%\bin\gcc.exe"
)

if not defined CC (
    for %%P in (
        "%SystemDrive%\msys64\mingw32\bin\gcc.exe"
        "%SystemDrive%\Ruby34-x64\msys64\mingw32\bin\gcc.exe"
        "\msys64\mingw32\bin\gcc.exe"
    ) do (
        if not defined CC if exist %%P set "CC=%%~P"
    )
)

if not defined CC set "CC=gcc"

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
"!CC!" -m32 -shared -O2 -Wall -Wextra -Wno-cast-function-type -Wno-unused-parameter "%SRC_PREFIX%utf8_hook.c" "%DEF%" -o "%OUTPUT%" -static-libgcc -Wl,--enable-stdcall-fixup -lgdi32 -luser32 -lkernel32 -lshell32

if !ERRORLEVEL! equ 0 (
    echo Build succeeded: %OUTPUT%
    dir "%OUTPUT%" | findstr "%OUTPUT%"
) else (
    echo Build failed with error !ERRORLEVEL!
)
endlocal
