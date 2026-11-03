
#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef LOCALE_IDEFAULTOEMCODEPAGE
#define LOCALE_IDEFAULTOEMCODEPAGE 0x0000000B
#endif
#ifndef LOCALE_IDEFAULTANSICODEPAGE
#define LOCALE_IDEFAULTANSICODEPAGE 0x00001004
#endif
#ifndef LOCALE_IDEFAULTCODEPAGE
#define LOCALE_IDEFAULTCODEPAGE 0x0000000B
#endif

// Real function pointers
static int (WINAPI *pReal_MultiByteToWideChar)(UINT, DWORD, LPCCH, int, LPWSTR, int) = NULL;
static int (WINAPI *pReal_WideCharToMultiByte)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL) = NULL;
static UINT (WINAPI *pReal_GetACP)(void) = NULL;
static UINT (WINAPI *pReal_GetOEMCP)(void) = NULL;
static BOOL (WINAPI *pReal_GetCPInfo)(UINT, LPCPINFO) = NULL;
static int (WINAPI *pReal_GetLocaleInfoA)(LCID, LCTYPE, LPSTR, int) = NULL;
static LCID (WINAPI *pReal_GetThreadLocale)(void) = NULL;
static int (WINAPI *pReal_CompareStringA)(LCID, DWORD, LPCSTR, int, LPCSTR, int) = NULL;
static BOOL (WINAPI *pReal_IsDBCSLeadByte)(BYTE) = NULL;
static BOOL (WINAPI *pReal_IsDBCSLeadByteEx)(UINT, BYTE) = NULL;

static LPSTR (WINAPI *pReal_CharNextA)(LPCSTR) = NULL;
static LPSTR (WINAPI *pReal_CharPrevA)(LPCSTR, LPCSTR) = NULL;
static DWORD (WINAPI *pReal_CharUpperBuffA)(LPSTR, DWORD) = NULL;
static DWORD (WINAPI *pReal_CharLowerBuffA)(LPSTR, DWORD) = NULL;
static LPSTR (WINAPI *pReal_CharLowerA)(LPSTR) = NULL;
static LPSTR (WINAPI *pReal_CharUpperA)(LPSTR) = NULL;

static HWND (WINAPI *pReal_CreateWindowExA)(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID) = NULL;
static BOOL (WINAPI *pReal_SetWindowTextA)(HWND, LPCSTR) = NULL;
static LRESULT (WINAPI *pReal_DefWindowProcA)(HWND, UINT, WPARAM, LPARAM) = NULL;
static LRESULT (WINAPI *pReal_SendMessageA)(HWND, UINT, WPARAM, LPARAM) = NULL;
static int (WINAPI *pReal_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT) = NULL;

static HFONT (WINAPI *pReal_CreateFontIndirectA)(const LOGFONTA *) = NULL;
static HFONT (WINAPI *pReal_CreateFontA)(int, int, int, int, int, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPCSTR) = NULL;
static BOOL (WINAPI *pReal_ExtTextOutA)(HDC, int, int, UINT, const RECT *, LPCSTR, UINT, const INT *) = NULL;
static BOOL (WINAPI *pReal_TextOutA)(HDC, int, int, LPCSTR, int) = NULL;
static BOOL (WINAPI *pReal_GetTextExtentPoint32A)(HDC, LPCSTR, int, LPSIZE) = NULL;
static BOOL (WINAPI *pReal_GetTextExtentPointA)(HDC, LPCSTR, int, LPSIZE) = NULL;
static int (WINAPI *pReal_DrawTextA)(HDC, LPCSTR, int, LPRECT, UINT) = NULL;
static int (WINAPI *pReal_DrawTextExA)(HDC, LPSTR, int, LPRECT, UINT, LPDRAWTEXTPARAMS) = NULL;
static int (WINAPI *pReal_EnumFontFamiliesExA)(HDC, LPLOGFONTA, FONTENUMPROCA, LPARAM, DWORD) = NULL;

static HANDLE (WINAPI *pReal_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = NULL;
static DWORD (WINAPI *pReal_GetFileAttributesA)(LPCSTR) = NULL;
static BOOL (WINAPI *pReal_GetFileAttributesExA)(LPCSTR, GET_FILEEX_INFO_LEVELS, LPVOID) = NULL;
static HANDLE (WINAPI *pReal_FindFirstFileA)(LPCSTR, LPWIN32_FIND_DATAA) = NULL;
static BOOL (WINAPI *pReal_FindNextFileA)(HANDLE, LPWIN32_FIND_DATAA) = NULL;
static BOOL (WINAPI *pReal_CreateDirectoryA)(LPCSTR, LPSECURITY_ATTRIBUTES) = NULL;
static BOOL (WINAPI *pReal_RemoveDirectoryA)(LPCSTR) = NULL;
static BOOL (WINAPI *pReal_DeleteFileA)(LPCSTR) = NULL;
static HMODULE (WINAPI *pReal_LoadLibraryA)(LPCSTR) = NULL;
static HMODULE (WINAPI *pReal_LoadLibraryExA)(LPCSTR, HANDLE, DWORD) = NULL;

// Smart hook supporting both 5-byte prologue and indirect jump thunks
static void *smart_hook(void *target, void *detour) {
    if (!target || !detour) return NULL;
    BYTE *b = (BYTE *)target;

    // Indirect jump: FF 25 [slot]
    if (b[0] == 0xFF && b[1] == 0x25) {
        void **slot = *(void ***)(b + 2);
        DWORD old;
        VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &old);
        void *orig = *slot;
        *slot = detour;
        VirtualProtect(slot, sizeof(void *), old, &old);
        return orig;
    }

    // Standard 5-byte prologue
    BYTE *tramp = (BYTE *)VirtualAlloc(NULL, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) return NULL;

    memcpy(tramp, b, 5);
    tramp[5] = 0xE9;
    *(DWORD *)(tramp + 6) = (DWORD)(b + 5) - (DWORD)(tramp + 5) - 5;

    DWORD old;
    VirtualProtect(b, 5, PAGE_EXECUTE_READWRITE, &old);
    b[0] = 0xE9;
    *(DWORD *)(b + 1) = (DWORD)detour - (DWORD)b - 5;
    VirtualProtect(b, 5, old, &old);

    return tramp;
}

// Code page & locale hooks
static UINT WINAPI Hook_GetACP(void) {
    return 936;
}

static UINT WINAPI Hook_GetOEMCP(void) {
    return 936;
}

static LCID WINAPI Hook_GetThreadLocale(void) {
    return 0x0804; // Chinese (Simplified, PRC)
}

static BOOL WINAPI Hook_GetCPInfo(UINT CodePage, LPCPINFO lpCPInfo) {
    if (CodePage == CP_ACP || CodePage == CP_OEMCP || CodePage == CP_THREAD_ACP || CodePage == 65001) {
        CodePage = 936;
    }
    return pReal_GetCPInfo(CodePage, lpCPInfo);
}

static int WINAPI Hook_GetLocaleInfoA(LCID Locale, LCTYPE LCType, LPSTR lpLCData, int cchData) {
    if ((LCType & 0xFFFF) == LOCALE_IDEFAULTANSICODEPAGE ||
        (LCType & 0xFFFF) == LOCALE_IDEFAULTOEMCODEPAGE ||
        (LCType & 0xFFFF) == LOCALE_IDEFAULTCODEPAGE) {
        if (cchData == 0) return 4;
        strncpy(lpLCData, "936", cchData);
        return (int)strlen(lpLCData) + 1;
    }
    return pReal_GetLocaleInfoA(Locale, LCType, lpLCData, cchData);
}

static int WINAPI Hook_MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar) {
    if (CodePage == CP_ACP || CodePage == CP_OEMCP || CodePage == CP_THREAD_ACP || CodePage == 65001) {
        CodePage = 936;
    }
    return pReal_MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}

static int WINAPI Hook_WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar) {
    if (CodePage == CP_ACP || CodePage == CP_OEMCP || CodePage == CP_THREAD_ACP || CodePage == 65001) {
        CodePage = 936;
    }
    return pReal_WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}

static BOOL WINAPI Hook_IsDBCSLeadByte(BYTE TestChar) {
    return (TestChar >= 0x81 && TestChar <= 0xFE);
}

static BOOL WINAPI Hook_IsDBCSLeadByteEx(UINT CodePage, BYTE TestChar) {
    if (CodePage == CP_ACP || CodePage == CP_OEMCP || CodePage == 936 || CodePage == 65001) {
        return (TestChar >= 0x81 && TestChar <= 0xFE);
    }
    return pReal_IsDBCSLeadByteEx(CodePage, TestChar);
}

static LPSTR WINAPI Hook_CharNextA(LPCSTR lpCurrentChar) {
    if (!lpCurrentChar || !*lpCurrentChar) return (LPSTR)lpCurrentChar;
    unsigned char c = (unsigned char)*lpCurrentChar;
    if (c >= 0x81 && c <= 0xFE && *(lpCurrentChar + 1)) {
        return (LPSTR)(lpCurrentChar + 2);
    }
    return (LPSTR)(lpCurrentChar + 1);
}

static LPSTR WINAPI Hook_CharPrevA(LPCSTR lpStart, LPCSTR lpCurrentChar) {
    if (!lpStart || !lpCurrentChar || lpCurrentChar <= lpStart) return (LPSTR)lpStart;
    LPCSTR p = lpStart;
    LPCSTR prev = lpStart;
    while (p < lpCurrentChar) {
        prev = p;
        p = Hook_CharNextA(p);
    }
    return (LPSTR)prev;
}

static DWORD WINAPI Hook_CharUpperBuffA(LPSTR lpsz, DWORD cchLength) {
    if (!lpsz || cchLength == 0) return 0;
    DWORD i = 0;
    while (i < cchLength) {
        unsigned char c = (unsigned char)lpsz[i];
        if (c >= 0x81 && c <= 0xFE && (i + 1 < cchLength)) {
            i += 2;
        } else {
            if (c >= 'a' && c <= 'z') lpsz[i] = (char)(c - 'a' + 'A');
            i += 1;
        }
    }
    return cchLength;
}

static DWORD WINAPI Hook_CharLowerBuffA(LPSTR lpsz, DWORD cchLength) {
    if (!lpsz || cchLength == 0) return 0;
    DWORD i = 0;
    while (i < cchLength) {
        unsigned char c = (unsigned char)lpsz[i];
        if (c >= 0x81 && c <= 0xFE && (i + 1 < cchLength)) {
            i += 2;
        } else {
            if (c >= 'A' && c <= 'Z') lpsz[i] = (char)(c - 'A' + 'a');
            i += 1;
        }
    }
    return cchLength;
}

static LPSTR WINAPI Hook_CharLowerA(LPSTR lpsz) {
    if (!lpsz) return NULL;
    if ((ULONG_PTR)lpsz > 0xFFFF) {
        Hook_CharLowerBuffA(lpsz, (DWORD)strlen(lpsz));
        return lpsz;
    }
    unsigned char c = (unsigned char)(ULONG_PTR)lpsz;
    if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
    return (LPSTR)(ULONG_PTR)c;
}

static LPSTR WINAPI Hook_CharUpperA(LPSTR lpsz) {
    if (!lpsz) return NULL;
    if ((ULONG_PTR)lpsz > 0xFFFF) {
        Hook_CharUpperBuffA(lpsz, (DWORD)strlen(lpsz));
        return lpsz;
    }
    unsigned char c = (unsigned char)(ULONG_PTR)lpsz;
    if (c >= 'a' && c <= 'z') c = c - 'a' + 'A';
    return (LPSTR)(ULONG_PTR)c;
}

static int WINAPI Hook_CompareStringA(LCID Locale, DWORD dwCmpFlags, LPCSTR lpString1, int cchCount1, LPCSTR lpString2, int cchCount2) {
    int len1 = cchCount1;
    if (len1 == -1 && lpString1) len1 = (int)strlen(lpString1);
    int len2 = cchCount2;
    if (len2 == -1 && lpString2) len2 = (int)strlen(lpString2);

    int wlen1 = MultiByteToWideChar(936, 0, lpString1 ? lpString1 : "", len1, NULL, 0);
    int wlen2 = MultiByteToWideChar(936, 0, lpString2 ? lpString2 : "", len2, NULL, 0);
    WCHAR *w1 = (WCHAR *)malloc((wlen1 + 1) * sizeof(WCHAR));
    WCHAR *w2 = (WCHAR *)malloc((wlen2 + 1) * sizeof(WCHAR));
    MultiByteToWideChar(936, 0, lpString1 ? lpString1 : "", len1, w1, wlen1);
    MultiByteToWideChar(936, 0, lpString2 ? lpString2 : "", len2, w2, wlen2);
    w1[wlen1] = L'\0';
    w2[wlen2] = L'\0';

    int res = CompareStringW(0x0804, dwCmpFlags, w1, wlen1, w2, wlen2);
    free(w1);
    free(w2);
    return res;
}

static HFONT WINAPI Hook_CreateFontIndirectA(const LOGFONTA *lplf) {
    if (!lplf) return pReal_CreateFontIndirectA(lplf);
    LOGFONTW lfw;
    memcpy(&lfw, lplf, sizeof(LOGFONTA) - LF_FACESIZE);
    MultiByteToWideChar(936, 0, lplf->lfFaceName, -1, lfw.lfFaceName, LF_FACESIZE);
    lfw.lfCharSet = GB2312_CHARSET;

    if (wcsstr(lfw.lfFaceName, L"明朝") != NULL ||
        wcsstr(lfw.lfFaceName, L"Mincho") != NULL ||
        wcsstr(lfw.lfFaceName, L"宋体") != NULL ||
        wcsstr(lfw.lfFaceName, L"SimSun") != NULL) {
        wcscpy(lfw.lfFaceName, L"SimSun");
    } else {
        wcscpy(lfw.lfFaceName, L"SimHei");
    }
    return CreateFontIndirectW(&lfw);
}

static HFONT WINAPI Hook_CreateFontA(int cHeight, int cWidth, int cEscapement, int cOrientation, int cWeight, DWORD bItalic, DWORD bUnderline, DWORD bStrikeOut, DWORD iCharSet, DWORD iOutPrecision, DWORD iClipPrecision, DWORD iQuality, DWORD iPitchAndFamily, LPCSTR pszFaceName) {
    WCHAR wFace[LF_FACESIZE] = {0};
    if (pszFaceName) {
        MultiByteToWideChar(936, 0, pszFaceName, -1, wFace, LF_FACESIZE);
    }
    if (wcsstr(wFace, L"明朝") != NULL ||
        wcsstr(wFace, L"Mincho") != NULL ||
        wcsstr(wFace, L"宋体") != NULL ||
        wcsstr(wFace, L"SimSun") != NULL) {
        wcscpy(wFace, L"SimSun");
    } else {
        wcscpy(wFace, L"SimHei");
    }
    return CreateFontW(cHeight, cWidth, cEscapement, cOrientation, cWeight, bItalic, bUnderline, bStrikeOut, GB2312_CHARSET, iOutPrecision, iClipPrecision, iQuality, iPitchAndFamily, wFace);
}

static BOOL WINAPI Hook_ExtTextOutA(HDC hdc, int x, int y, UINT options, const RECT *lprect, LPCSTR lpString, UINT c, const INT *lpDx) {
    if (!lpString || c == 0) return pReal_ExtTextOutA(hdc, x, y, options, lprect, lpString, c, lpDx);

    int wlen = MultiByteToWideChar(936, 0, lpString, c, NULL, 0);
    if (wlen <= 0) return pReal_ExtTextOutA(hdc, x, y, options, lprect, lpString, c, lpDx);
    WCHAR *wbuf = (WCHAR *)malloc((wlen + 1) * sizeof(WCHAR));
    MultiByteToWideChar(936, 0, lpString, c, wbuf, wlen);
    wbuf[wlen] = L'\0';

    BOOL res;
    if (lpDx == NULL) {
        res = ExtTextOutW(hdc, x, y, options, lprect, wbuf, wlen, NULL);
    } else {
        INT *wDx = (INT *)malloc(wlen * sizeof(INT));
        int wi = 0;
        for (UINT i = 0; i < c && wi < wlen; ) {
            unsigned char ch = (unsigned char)lpString[i];
            if (ch >= 0x81 && ch <= 0xFE && (i + 1 < c)) {
                wDx[wi++] = lpDx[i] + lpDx[i + 1];
                i += 2;
            } else {
                wDx[wi++] = lpDx[i];
                i += 1;
            }
        }
        res = ExtTextOutW(hdc, x, y, options, lprect, wbuf, wi, wDx);
        free(wDx);
    }
    free(wbuf);
    return res;
}

static BOOL WINAPI Hook_TextOutA(HDC hdc, int x, int y, LPCSTR lpString, int c) {
    return Hook_ExtTextOutA(hdc, x, y, 0, NULL, lpString, c, NULL);
}

static BOOL WINAPI Hook_GetTextExtentPoint32A(HDC hdc, LPCSTR lpString, int c, LPSIZE lpSize) {
    if (!lpString || c == 0) return pReal_GetTextExtentPoint32A(hdc, lpString, c, lpSize);
    int wlen = MultiByteToWideChar(936, 0, lpString, c, NULL, 0);
    if (wlen <= 0) return pReal_GetTextExtentPoint32A(hdc, lpString, c, lpSize);
    WCHAR *wbuf = (WCHAR *)malloc((wlen + 1) * sizeof(WCHAR));
    MultiByteToWideChar(936, 0, lpString, c, wbuf, wlen);
    BOOL res = GetTextExtentPoint32W(hdc, wbuf, wlen, lpSize);
    free(wbuf);
    return res;
}

static BOOL WINAPI Hook_GetTextExtentPointA(HDC hdc, LPCSTR lpString, int c, LPSIZE lpSize) {
    return Hook_GetTextExtentPoint32A(hdc, lpString, c, lpSize);
}

static int WINAPI Hook_DrawTextA(HDC hdc, LPCSTR lpchText, int cchText, LPRECT lprc, UINT format) {
    if (!lpchText) return 0;
    int len = cchText;
    if (len == -1) len = (int)strlen(lpchText);
    int wlen = MultiByteToWideChar(936, 0, lpchText, len, NULL, 0);
    if (wlen <= 0) return pReal_DrawTextA(hdc, lpchText, cchText, lprc, format);
    WCHAR *wbuf = (WCHAR *)malloc((wlen + 1) * sizeof(WCHAR));
    MultiByteToWideChar(936, 0, lpchText, len, wbuf, wlen);
    wbuf[wlen] = L'\0';
    int res = DrawTextW(hdc, wbuf, (cchText == -1 ? -1 : wlen), lprc, format);
    free(wbuf);
    return res;
}

static int WINAPI Hook_DrawTextExA(HDC hdc, LPSTR lpchText, int cchText, LPRECT lprc, UINT format, LPDRAWTEXTPARAMS lpdtp) {
    if (!lpchText) return 0;
    int len = cchText;
    if (len == -1) len = (int)strlen(lpchText);
    int wlen = MultiByteToWideChar(936, 0, lpchText, len, NULL, 0);
    if (wlen <= 0) return pReal_DrawTextExA(hdc, lpchText, cchText, lprc, format, lpdtp);
    WCHAR *wbuf = (WCHAR *)malloc((wlen + 1) * sizeof(WCHAR));
    MultiByteToWideChar(936, 0, lpchText, len, wbuf, wlen);
    wbuf[wlen] = L'\0';
    int res = DrawTextExW(hdc, wbuf, (cchText == -1 ? -1 : wlen), lprc, format, lpdtp);
    free(wbuf);
    return res;
}

static int WINAPI Hook_EnumFontFamiliesExA(HDC hdc, LPLOGFONTA lpLogfont, FONTENUMPROCA lpProc, LPARAM lParam, DWORD dwFlags) {
    int res = pReal_EnumFontFamiliesExA(hdc, lpLogfont, lpProc, lParam, dwFlags);
    if (lpLogfont && (lpLogfont->lfCharSet == 134 || lpLogfont->lfCharSet == DEFAULT_CHARSET)) {
        ENUMLOGFONTEXA elf = {0};
        NEWTEXTMETRICEXA ntm = {0};
        elf.elfLogFont.lfCharSet = 134;
        elf.elfLogFont.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
        strcpy(elf.elfLogFont.lfFaceName, "SimSun");
        strcpy((char *)elf.elfFullName, "SimSun");
        lpProc((const LOGFONTA *)&elf, (const TEXTMETRICA *)&ntm, TRUETYPE_FONTTYPE, lParam);

        elf.elfLogFont.lfPitchAndFamily = VARIABLE_PITCH | FF_SWISS;
        strcpy(elf.elfLogFont.lfFaceName, "SimHei");
        strcpy((char *)elf.elfFullName, "SimHei");
        lpProc((const LOGFONTA *)&elf, (const TEXTMETRICA *)&ntm, TRUETYPE_FONTTYPE, lParam);
    }
    return res;
}

// Window & UI hooks
static HWND WINAPI Hook_CreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam) {
    WCHAR *wClass = NULL;
    WCHAR *wName = NULL;
    if (((ULONG_PTR)lpClassName > 0xFFFF) && lpClassName) {
        int l = MultiByteToWideChar(936, 0, lpClassName, -1, NULL, 0);
        if (l > 0) {
            wClass = (WCHAR *)malloc(l * sizeof(WCHAR));
            MultiByteToWideChar(936, 0, lpClassName, -1, wClass, l);
        }
    }
    if (lpWindowName) {
        int l = MultiByteToWideChar(936, 0, lpWindowName, -1, NULL, 0);
        if (l > 0) {
            wName = (WCHAR *)malloc(l * sizeof(WCHAR));
            MultiByteToWideChar(936, 0, lpWindowName, -1, wName, l);
        }
    }
    HWND res = CreateWindowExW(dwExStyle, wClass ? wClass : (LPCWSTR)lpClassName, wName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
    if (wClass) free(wClass);
    if (wName) free(wName);
    return res;
}

static BOOL WINAPI Hook_SetWindowTextA(HWND hWnd, LPCSTR lpString) {
    if (!lpString) return pReal_SetWindowTextA(hWnd, lpString);
    int len = MultiByteToWideChar(936, 0, lpString, -1, NULL, 0);
    if (len <= 0) return pReal_SetWindowTextA(hWnd, lpString);
    WCHAR *wbuf = (WCHAR *)malloc(len * sizeof(WCHAR));
    MultiByteToWideChar(936, 0, lpString, -1, wbuf, len);
    BOOL res = SetWindowTextW(hWnd, wbuf);
    free(wbuf);
    return res;
}

static LRESULT WINAPI Hook_DefWindowProcA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    if (Msg == WM_SETTEXT && lParam != 0) {
        LPCSTR str = (LPCSTR)lParam;
        int wlen = MultiByteToWideChar(936, 0, str, -1, NULL, 0);
        if (wlen > 0) {
            WCHAR *wbuf = (WCHAR *)malloc(wlen * sizeof(WCHAR));
            MultiByteToWideChar(936, 0, str, -1, wbuf, wlen);
            LRESULT res = DefWindowProcW(hWnd, WM_SETTEXT, wParam, (LPARAM)wbuf);
            free(wbuf);
            return res;
        }
    }
    return pReal_DefWindowProcA(hWnd, Msg, wParam, lParam);
}

static LRESULT WINAPI Hook_SendMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    if (Msg == WM_SETTEXT && lParam != 0) {
        LPCSTR str = (LPCSTR)lParam;
        int wlen = MultiByteToWideChar(936, 0, str, -1, NULL, 0);
        if (wlen > 0) {
            WCHAR *wbuf = (WCHAR *)malloc(wlen * sizeof(WCHAR));
            MultiByteToWideChar(936, 0, str, -1, wbuf, wlen);
            LRESULT res = SendMessageW(hWnd, WM_SETTEXT, wParam, (LPARAM)wbuf);
            free(wbuf);
            return res;
        }
    }
    return pReal_SendMessageA(hWnd, Msg, wParam, lParam);
}

static int WINAPI Hook_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    int lenText = MultiByteToWideChar(936, 0, lpText ? lpText : "", -1, NULL, 0);
    int lenCap = MultiByteToWideChar(936, 0, lpCaption ? lpCaption : "", -1, NULL, 0);
    WCHAR *wText = (WCHAR *)malloc((lenText + 1) * sizeof(WCHAR));
    WCHAR *wCap = (WCHAR *)malloc((lenCap + 1) * sizeof(WCHAR));
    MultiByteToWideChar(936, 0, lpText ? lpText : "", -1, wText, lenText + 1);
    MultiByteToWideChar(936, 0, lpCaption ? lpCaption : "", -1, wCap, lenCap + 1);
    int res = MessageBoxW(hWnd, wText, wCap, uType);
    free(wText);
    free(wCap);
    return res;
}

// -------------------------------------------------------------
// File System Hooks
// -------------------------------------------------------------

static BOOL IsValidUTF8(const char *str) {
    if (!str) return FALSE;
    const unsigned char *bytes = (const unsigned char *)str;
    BOOL hasNonAscii = FALSE;
    while (*bytes) {
        if (*bytes >= 0x80) {
            hasNonAscii = TRUE;
            if ((*bytes & 0xE0) == 0xC0) {
                if ((bytes[1] & 0xC0) != 0x80) return FALSE;
                bytes += 2;
            } else if ((*bytes & 0xF0) == 0xE0) {
                if ((bytes[1] & 0xC0) != 0x80 || (bytes[2] & 0xC0) != 0x80) return FALSE;
                bytes += 3;
            } else if ((*bytes & 0xF8) == 0xF0) {
                if ((bytes[1] & 0xC0) != 0x80 || (bytes[2] & 0xC0) != 0x80 || (bytes[3] & 0xC0) != 0x80) return FALSE;
                bytes += 4;
            } else {
                return FALSE;
            }
        } else {
            bytes++;
        }
    }
    return hasNonAscii;
}

static HANDLE WINAPI Hook_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    if (!lpFileName) return INVALID_HANDLE_VALUE;

    // 1. If valid UTF-8, try real CreateFileA first
    if (IsValidUTF8(lpFileName)) {
        HANDLE h = pReal_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        if (h != INVALID_HANDLE_VALUE) return h;
    }

    // 2. Try CP936 -> CreateFileW (matches EVB virtual files)
    WCHAR wPath[MAX_PATH * 2] = {0};
    MultiByteToWideChar(936, 0, lpFileName, -1, wPath, MAX_PATH * 2 - 1);
    HANDLE h = CreateFileW(wPath, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    if (h != INVALID_HANDLE_VALUE) return h;

    // 3. Try CP932 -> CreateFileW (for reading Japanese assets if any)
    if ((dwDesiredAccess & GENERIC_WRITE) == 0) {
        WCHAR wPathSjis[MAX_PATH * 2] = {0};
        MultiByteToWideChar(932, 0, lpFileName, -1, wPathSjis, MAX_PATH * 2 - 1);
        if (wcscmp(wPath, wPathSjis) != 0) {
            h = CreateFileW(wPathSjis, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
            if (h != INVALID_HANDLE_VALUE) return h;
        }
    }

    return pReal_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

static DWORD WINAPI Hook_GetFileAttributesA(LPCSTR lpFileName) {
    if (!lpFileName) return INVALID_FILE_ATTRIBUTES;

    if (IsValidUTF8(lpFileName)) {
        DWORD attr = pReal_GetFileAttributesA(lpFileName);
        if (attr != INVALID_FILE_ATTRIBUTES) return attr;
    }

    WCHAR wPath[MAX_PATH * 2] = {0};
    MultiByteToWideChar(936, 0, lpFileName, -1, wPath, MAX_PATH * 2 - 1);
    DWORD attr = GetFileAttributesW(wPath);
    if (attr != INVALID_FILE_ATTRIBUTES) return attr;

    WCHAR wPathSjis[MAX_PATH * 2] = {0};
    MultiByteToWideChar(932, 0, lpFileName, -1, wPathSjis, MAX_PATH * 2 - 1);
    if (wcscmp(wPath, wPathSjis) != 0) {
        attr = GetFileAttributesW(wPathSjis);
        if (attr != INVALID_FILE_ATTRIBUTES) return attr;
    }

    return pReal_GetFileAttributesA(lpFileName);
}

static BOOL WINAPI Hook_GetFileAttributesExA(LPCSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation) {
    if (!lpFileName) return FALSE;

    if (IsValidUTF8(lpFileName)) {
        BOOL res = pReal_GetFileAttributesExA(lpFileName, fInfoLevelId, lpFileInformation);
        if (res) return res;
    }

    WCHAR wPath[MAX_PATH * 2] = {0};
    MultiByteToWideChar(936, 0, lpFileName, -1, wPath, MAX_PATH * 2 - 1);
    BOOL res = GetFileAttributesExW(wPath, fInfoLevelId, lpFileInformation);
    if (res) return res;

    WCHAR wPathSjis[MAX_PATH * 2] = {0};
    MultiByteToWideChar(932, 0, lpFileName, -1, wPathSjis, MAX_PATH * 2 - 1);
    if (wcscmp(wPath, wPathSjis) != 0) {
        res = GetFileAttributesExW(wPathSjis, fInfoLevelId, lpFileInformation);
        if (res) return res;
    }

    return pReal_GetFileAttributesExA(lpFileName, fInfoLevelId, lpFileInformation);
}

static HANDLE WINAPI Hook_FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) {
    if (!lpFileName || !lpFindFileData) return INVALID_HANDLE_VALUE;

    if (IsValidUTF8(lpFileName)) {
        HANDLE h = pReal_FindFirstFileA(lpFileName, lpFindFileData);
        if (h != INVALID_HANDLE_VALUE) return h;
    }

    WCHAR wPath[MAX_PATH * 2] = {0};
    MultiByteToWideChar(936, 0, lpFileName, -1, wPath, MAX_PATH * 2 - 1);
    WIN32_FIND_DATAW fdW;
    HANDLE h = FindFirstFileW(wPath, &fdW);
    if (h == INVALID_HANDLE_VALUE) {
        WCHAR wPathSjis[MAX_PATH * 2] = {0};
        MultiByteToWideChar(932, 0, lpFileName, -1, wPathSjis, MAX_PATH * 2 - 1);
        if (wcscmp(wPath, wPathSjis) != 0) {
            h = FindFirstFileW(wPathSjis, &fdW);
        }
    }
    if (h != INVALID_HANDLE_VALUE) {
        lpFindFileData->dwFileAttributes = fdW.dwFileAttributes;
        lpFindFileData->ftCreationTime = fdW.ftCreationTime;
        lpFindFileData->ftLastAccessTime = fdW.ftLastAccessTime;
        lpFindFileData->ftLastWriteTime = fdW.ftLastWriteTime;
        lpFindFileData->nFileSizeHigh = fdW.nFileSizeHigh;
        lpFindFileData->nFileSizeLow = fdW.nFileSizeLow;
        lpFindFileData->dwReserved0 = fdW.dwReserved0;
        lpFindFileData->dwReserved1 = fdW.dwReserved1;
        WideCharToMultiByte(936, 0, fdW.cFileName, -1, lpFindFileData->cFileName, MAX_PATH, NULL, NULL);
        WideCharToMultiByte(936, 0, fdW.cAlternateFileName, -1, lpFindFileData->cAlternateFileName, 14, NULL, NULL);
        return h;
    }
    return pReal_FindFirstFileA(lpFileName, lpFindFileData);
}

static BOOL WINAPI Hook_FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) {
    if (!lpFindFileData) return FALSE;
    WIN32_FIND_DATAW fdW;
    BOOL res = FindNextFileW(hFindFile, &fdW);
    if (res) {
        lpFindFileData->dwFileAttributes = fdW.dwFileAttributes;
        lpFindFileData->ftCreationTime = fdW.ftCreationTime;
        lpFindFileData->ftLastAccessTime = fdW.ftLastAccessTime;
        lpFindFileData->ftLastWriteTime = fdW.ftLastWriteTime;
        lpFindFileData->nFileSizeHigh = fdW.nFileSizeHigh;
        lpFindFileData->nFileSizeLow = fdW.nFileSizeLow;
        lpFindFileData->dwReserved0 = fdW.dwReserved0;
        lpFindFileData->dwReserved1 = fdW.dwReserved1;
        WideCharToMultiByte(936, 0, fdW.cFileName, -1, lpFindFileData->cFileName, MAX_PATH, NULL, NULL);
        WideCharToMultiByte(936, 0, fdW.cAlternateFileName, -1, lpFindFileData->cAlternateFileName, 14, NULL, NULL);
        return TRUE;
    }
    return pReal_FindNextFileA(hFindFile, lpFindFileData);
}

static BOOL WINAPI Hook_CreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes) {
    if (!lpPathName) return FALSE;
    if (IsValidUTF8(lpPathName)) {
        BOOL res = pReal_CreateDirectoryA(lpPathName, lpSecurityAttributes);
        if (res || GetLastError() == ERROR_ALREADY_EXISTS) return res;
    }
    WCHAR wPath[MAX_PATH * 2] = {0};
    MultiByteToWideChar(936, 0, lpPathName, -1, wPath, MAX_PATH * 2 - 1);
    return CreateDirectoryW(wPath, lpSecurityAttributes);
}

static BOOL WINAPI Hook_RemoveDirectoryA(LPCSTR lpPathName) {
    if (!lpPathName) return FALSE;
    if (IsValidUTF8(lpPathName)) {
        BOOL res = pReal_RemoveDirectoryA(lpPathName);
        if (res) return res;
    }
    WCHAR wPath[MAX_PATH * 2] = {0};
    MultiByteToWideChar(936, 0, lpPathName, -1, wPath, MAX_PATH * 2 - 1);
    return RemoveDirectoryW(wPath);
}

static BOOL WINAPI Hook_DeleteFileA(LPCSTR lpFileName) {
    if (!lpFileName) return FALSE;
    if (IsValidUTF8(lpFileName)) {
        BOOL res = pReal_DeleteFileA(lpFileName);
        if (res) return res;
    }
    WCHAR wPath[MAX_PATH * 2] = {0};
    MultiByteToWideChar(936, 0, lpFileName, -1, wPath, MAX_PATH * 2 - 1);
    return DeleteFileW(wPath);
}

static HMODULE WINAPI Hook_LoadLibraryA(LPCSTR lpLibFileName) {
    if (!lpLibFileName) return NULL;
    HMODULE h = pReal_LoadLibraryA(lpLibFileName);
    if (h) return h;

    WCHAR wPath[MAX_PATH * 2] = {0};
    MultiByteToWideChar(936, 0, lpLibFileName, -1, wPath, MAX_PATH * 2 - 1);
    h = LoadLibraryW(wPath);
    if (h) return h;

    WCHAR wPathSjis[MAX_PATH * 2] = {0};
    MultiByteToWideChar(932, 0, lpLibFileName, -1, wPathSjis, MAX_PATH * 2 - 1);
    if (wcscmp(wPath, wPathSjis) != 0) {
        h = LoadLibraryW(wPathSjis);
    }
    return h;
}

static HMODULE WINAPI Hook_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    if (!lpLibFileName) return NULL;
    HMODULE h = pReal_LoadLibraryExA(lpLibFileName, hFile, dwFlags);
    if (h) return h;

    WCHAR wPath[MAX_PATH * 2] = {0};
    MultiByteToWideChar(936, 0, lpLibFileName, -1, wPath, MAX_PATH * 2 - 1);
    h = LoadLibraryExW(wPath, hFile, dwFlags);
    if (h) return h;

    WCHAR wPathSjis[MAX_PATH * 2] = {0};
    MultiByteToWideChar(932, 0, lpLibFileName, -1, wPathSjis, MAX_PATH * 2 - 1);
    if (wcscmp(wPath, wPathSjis) != 0) {
        h = LoadLibraryExW(wPathSjis, hFile, dwFlags);
    }
    return h;
}

static void InstallHooks(void) {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    HMODULE hU32 = LoadLibraryA("user32.dll");
    HMODULE hG32 = LoadLibraryA("gdi32.dll");

    // Kernel32 code page / locale
    pReal_GetACP = (UINT (WINAPI *)(void))smart_hook(GetProcAddress(hK32, "GetACP"), (void *)Hook_GetACP);
    pReal_GetOEMCP = (UINT (WINAPI *)(void))smart_hook(GetProcAddress(hK32, "GetOEMCP"), (void *)Hook_GetOEMCP);
    pReal_GetCPInfo = (BOOL (WINAPI *)(UINT, LPCPINFO))smart_hook(GetProcAddress(hK32, "GetCPInfo"), (void *)Hook_GetCPInfo);
    pReal_GetLocaleInfoA = (int (WINAPI *)(LCID, LCTYPE, LPSTR, int))smart_hook(GetProcAddress(hK32, "GetLocaleInfoA"), (void *)Hook_GetLocaleInfoA);
    pReal_GetThreadLocale = (LCID (WINAPI *)(void))smart_hook(GetProcAddress(hK32, "GetThreadLocale"), (void *)Hook_GetThreadLocale);
    pReal_MultiByteToWideChar = (int (WINAPI *)(UINT, DWORD, LPCCH, int, LPWSTR, int))smart_hook(GetProcAddress(hK32, "MultiByteToWideChar"), (void *)Hook_MultiByteToWideChar);
    pReal_WideCharToMultiByte = (int (WINAPI *)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL))smart_hook(GetProcAddress(hK32, "WideCharToMultiByte"), (void *)Hook_WideCharToMultiByte);
    pReal_IsDBCSLeadByte = (BOOL (WINAPI *)(BYTE))smart_hook(GetProcAddress(hK32, "IsDBCSLeadByte"), (void *)Hook_IsDBCSLeadByte);
    pReal_IsDBCSLeadByteEx = (BOOL (WINAPI *)(UINT, BYTE))smart_hook(GetProcAddress(hK32, "IsDBCSLeadByteEx"), (void *)Hook_IsDBCSLeadByteEx);
    pReal_CompareStringA = (int (WINAPI *)(LCID, DWORD, LPCSTR, int, LPCSTR, int))smart_hook(GetProcAddress(hK32, "CompareStringA"), (void *)Hook_CompareStringA);

    // File APIs in kernel32
    pReal_CreateFileA = (HANDLE (WINAPI *)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))smart_hook(GetProcAddress(hK32, "CreateFileA"), (void *)Hook_CreateFileA);
    pReal_GetFileAttributesA = (DWORD (WINAPI *)(LPCSTR))smart_hook(GetProcAddress(hK32, "GetFileAttributesA"), (void *)Hook_GetFileAttributesA);
    pReal_GetFileAttributesExA = (BOOL (WINAPI *)(LPCSTR, GET_FILEEX_INFO_LEVELS, LPVOID))smart_hook(GetProcAddress(hK32, "GetFileAttributesExA"), (void *)Hook_GetFileAttributesExA);
    pReal_FindFirstFileA = (HANDLE (WINAPI *)(LPCSTR, LPWIN32_FIND_DATAA))smart_hook(GetProcAddress(hK32, "FindFirstFileA"), (void *)Hook_FindFirstFileA);
    pReal_FindNextFileA = (BOOL (WINAPI *)(HANDLE, LPWIN32_FIND_DATAA))smart_hook(GetProcAddress(hK32, "FindNextFileA"), (void *)Hook_FindNextFileA);
    pReal_CreateDirectoryA = (BOOL (WINAPI *)(LPCSTR, LPSECURITY_ATTRIBUTES))smart_hook(GetProcAddress(hK32, "CreateDirectoryA"), (void *)Hook_CreateDirectoryA);
    pReal_RemoveDirectoryA = (BOOL (WINAPI *)(LPCSTR))smart_hook(GetProcAddress(hK32, "RemoveDirectoryA"), (void *)Hook_RemoveDirectoryA);
    pReal_DeleteFileA = (BOOL (WINAPI *)(LPCSTR))smart_hook(GetProcAddress(hK32, "DeleteFileA"), (void *)Hook_DeleteFileA);
    pReal_LoadLibraryA = (HMODULE (WINAPI *)(LPCSTR))smart_hook(GetProcAddress(hK32, "LoadLibraryA"), (void *)Hook_LoadLibraryA);
    pReal_LoadLibraryExA = (HMODULE (WINAPI *)(LPCSTR, HANDLE, DWORD))smart_hook(GetProcAddress(hK32, "LoadLibraryExA"), (void *)Hook_LoadLibraryExA);

    // User32 strings / window / message
    pReal_CharNextA = (LPSTR (WINAPI *)(LPCSTR))smart_hook(GetProcAddress(hU32, "CharNextA"), (void *)Hook_CharNextA);
    pReal_CharPrevA = (LPSTR (WINAPI *)(LPCSTR, LPCSTR))smart_hook(GetProcAddress(hU32, "CharPrevA"), (void *)Hook_CharPrevA);
    pReal_CharUpperBuffA = (DWORD (WINAPI *)(LPSTR, DWORD))smart_hook(GetProcAddress(hU32, "CharUpperBuffA"), (void *)Hook_CharUpperBuffA);
    pReal_CharLowerBuffA = (DWORD (WINAPI *)(LPSTR, DWORD))smart_hook(GetProcAddress(hU32, "CharLowerBuffA"), (void *)Hook_CharLowerBuffA);
    pReal_CharLowerA = (LPSTR (WINAPI *)(LPSTR))smart_hook(GetProcAddress(hU32, "CharLowerA"), (void *)Hook_CharLowerA);
    pReal_CharUpperA = (LPSTR (WINAPI *)(LPSTR))smart_hook(GetProcAddress(hU32, "CharUpperA"), (void *)Hook_CharUpperA);

    pReal_CreateWindowExA = (HWND (WINAPI *)(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID))smart_hook(GetProcAddress(hU32, "CreateWindowExA"), (void *)Hook_CreateWindowExA);
    pReal_SetWindowTextA = (BOOL (WINAPI *)(HWND, LPCSTR))smart_hook(GetProcAddress(hU32, "SetWindowTextA"), (void *)Hook_SetWindowTextA);
    pReal_DefWindowProcA = (LRESULT (WINAPI *)(HWND, UINT, WPARAM, LPARAM))smart_hook(GetProcAddress(hU32, "DefWindowProcA"), (void *)Hook_DefWindowProcA);
    pReal_SendMessageA = (LRESULT (WINAPI *)(HWND, UINT, WPARAM, LPARAM))smart_hook(GetProcAddress(hU32, "SendMessageA"), (void *)Hook_SendMessageA);
    pReal_MessageBoxA = (int (WINAPI *)(HWND, LPCSTR, LPCSTR, UINT))smart_hook(GetProcAddress(hU32, "MessageBoxA"), (void *)Hook_MessageBoxA);

    // GDI32 font and text rendering
    pReal_CreateFontIndirectA = (HFONT (WINAPI *)(const LOGFONTA *))smart_hook(GetProcAddress(hG32, "CreateFontIndirectA"), (void *)Hook_CreateFontIndirectA);
    pReal_CreateFontA = (HFONT (WINAPI *)(int, int, int, int, int, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPCSTR))smart_hook(GetProcAddress(hG32, "CreateFontA"), (void *)Hook_CreateFontA);
    pReal_ExtTextOutA = (BOOL (WINAPI *)(HDC, int, int, UINT, const RECT *, LPCSTR, UINT, const INT *))smart_hook(GetProcAddress(hG32, "ExtTextOutA"), (void *)Hook_ExtTextOutA);
    pReal_TextOutA = (BOOL (WINAPI *)(HDC, int, int, LPCSTR, int))smart_hook(GetProcAddress(hG32, "TextOutA"), (void *)Hook_TextOutA);
    pReal_GetTextExtentPoint32A = (BOOL (WINAPI *)(HDC, LPCSTR, int, LPSIZE))smart_hook(GetProcAddress(hG32, "GetTextExtentPoint32A"), (void *)Hook_GetTextExtentPoint32A);
    pReal_GetTextExtentPointA = (BOOL (WINAPI *)(HDC, LPCSTR, int, LPSIZE))smart_hook(GetProcAddress(hG32, "GetTextExtentPointA"), (void *)Hook_GetTextExtentPointA);
    pReal_DrawTextA = (int (WINAPI *)(HDC, LPCSTR, int, LPRECT, UINT))smart_hook(GetProcAddress(hU32, "DrawTextA"), (void *)Hook_DrawTextA);
    pReal_DrawTextExA = (int (WINAPI *)(HDC, LPSTR, int, LPRECT, UINT, LPDRAWTEXTPARAMS))smart_hook(GetProcAddress(hU32, "DrawTextExA"), (void *)Hook_DrawTextExA);
    pReal_EnumFontFamiliesExA = (int (WINAPI *)(HDC, LPLOGFONTA, FONTENUMPROCA, LPARAM, DWORD))smart_hook(GetProcAddress(hG32, "EnumFontFamiliesExA"), (void *)Hook_EnumFontFamiliesExA);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        InstallHooks();
    }
    return TRUE;
}
