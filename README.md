# Bishoujo Mangekyou 3 - UTF-8 Locale Compatibility Hook

A compatibility proxy DLL (`version.dll`) for *Bishoujo Mangekyou -Kami ga Tsukuritamouta Shoujo-tachi-* (QLIE Engine) (Probably some other games using the same engine) to run correctly under modern Windows environments with the **"Beta: Use Unicode UTF-8 for worldwide language support"** locale enabled.

## Problem Background

In modern Windows systems with UTF-8 system code page (CP 65001) enabled:
1. **ANSI File APIs**: QLIE passes non-UTF8 multibyte path strings (such as Shift-JIS / GBK encoded script and asset paths like `Scenario\杮曇\k00OP_01.s`) to ANSI Win32 APIs (`CreateFileA`, `GetFileAttributesA`, etc.). Under UTF-8 locale, Windows decodes these bytes as UTF-8, resulting in invalid character replacements (`\uFFFD`), file not found errors, and fallback to Japanese encrypted script archives displayed as mojibake.
2. **Text Rendering**: GDI text rendering (`ExtTextOutA`, `GetTextExtentPoint32A`) and font creation (`CreateFontIndirectA`) require mapping GBK text to WideChar and selecting valid fonts (e.g. SimSun / SimHei) with proper character sets (`GB2312_CHARSET`).
3. **Save Directory**: Documents folder and save paths with multibyte names are corrupted without encoding translation.

## Solution

This project implements an in-process proxy DLL loaded via `version.dll` hijacking:
- **Encoding-Aware File I/O**: Detects UTF-8 versus multibyte strings; transparently converts legacy multibyte file paths (CP936/CP932) to wide strings and dispatches to Unicode Win32 APIs (`CreateFileW`, `GetFileAttributesW`, `FindFirstFileW`, etc.), enabling Enigma Virtual Box (EVB) virtual file resolution.
- **GDI & Font Hooking**: Intercepts `CreateFontIndirectA`, `ExtTextOutA`, `DrawTextA`, and font family enumeration to guarantee correct font linking, measurement, and Chinese glyph rasterization.
- **Locale Redirection**: Spoofs `GetACP`, `GetOEMCP`, `GetThreadLocale`, and multibyte string routines to Code Page 936.

## Building

Requires MinGW-w64 (32-bit `gcc`):

```cmd
build.bat
```

Or with Make:

```bash
make
```

## Installation

Copy the built `version.dll` into the game root directory alongside the game executable.
