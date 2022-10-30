// ReactOS Japanese Package
// Copyright (C) 2019 Katayama Hirofumi MZ.
// This file is public domain software.
#include "MRegKey.hpp"
#include <cstdio>
#include <shlwapi.h>

#ifndef ARRAYSIZE
    #define ARRAYSIZE(array) (sizeof(array) / sizeof(array[0]))
#endif

LPTSTR LoadStringDx(INT nID)
{
    static UINT s_index = 0;
    const UINT cchBuffMax = 1024;
    static TCHAR s_sz[2][cchBuffMax];

    TCHAR *pszBuff = s_sz[s_index];
    s_index = (s_index + 1) % ARRAYSIZE(s_sz);
    pszBuff[0] = 0;
    if (!::LoadString(NULL, nID, pszBuff, cchBuffMax))
        assert(0);
    return pszBuff;
}

struct FONTSUBST
{
    LPCWSTR from, to;
};

// Japanese
WCHAR JF_LocalName0[] = {0xFF2D, 0xFF33, ' ', 0x660E, 0x671D, 0};                           // MS Mincho
WCHAR JF_LocalName1[] = {0xFF2D, 0xFF33, ' ', 0xFF30, 0x660E, 0x671D, 0};                   // MS PMincho
WCHAR JF_LocalName2[] = {0xFF2D, 0xFF33, ' ', 0x30B4, 0x30B7, 0x30C3, 0x30AF, 0};           // MS Gothic
WCHAR JF_LocalName3[] = {0xFF2D, 0xFF33, ' ', 0xFF30, 0x30B4, 0x30B7, 0x30C3, 0x30AF, 0};   // MS PGothic

static const FONTSUBST NEU_MapForInstall[] =
{
    { L"MS Mincho",       NULL },
    { L"MS Gothic",       NULL },
    { L"MS PMincho",      NULL },
    { L"MS PGothic",      NULL },
    { L"MS UI Gothic",    NULL },
};

static const FONTSUBST JPN_MapForInstall[] =
{
    { JF_LocalName0,      NULL },
    { JF_LocalName2,      NULL },
    { JF_LocalName1,      NULL },
    { JF_LocalName3,      NULL },
    { L"Tahoma",          L"MS UI Gothic" },
    { L"System",          L"MS UI Gothic" },
};

static const FONTSUBST NEU_MapForUninstallNoDroid[] =
{
    { L"MS UI Gothic",    NULL },
    { L"MS Mincho",       NULL },
    { L"MS PMincho",      NULL },
    { L"MS Gothic",       NULL },
    { L"MS PGothic",      NULL },
    { L"MS UI Gothic",    NULL },
    { L"System",          NULL },
    { L"Tahoma",          NULL },
};

static const FONTSUBST JPN_MapForUninstallNoDroid[] =
{
    { JF_LocalName0,      NULL },
    { JF_LocalName1,      NULL },
    { JF_LocalName2,      NULL },
    { JF_LocalName3,      NULL },
    { L"System",          NULL },
    { L"Tahoma",          NULL },
};

static const FONTSUBST NEU_MapForUninstallWithDroid[] =
{
    { L"MS UI Gothic",    L"Droid Sans Fallback" },
    { L"MS Mincho",       L"Droid Sans Fallback" },
    { L"MS PMincho",      L"Droid Sans Fallback" },
    { L"MS Gothic",       L"Droid Sans Fallback" },
    { L"MS PGothic",      L"Droid Sans Fallback" },
    { L"MS UI Gothic",    L"Droid Sans Fallback" },
    { L"System",          NULL },
    { L"Tahoma",          NULL },
};

static const FONTSUBST JPN_MapForUninstallWithDroid[] =
{
    { JF_LocalName0,      L"Droid Sans Fallback" },
    { JF_LocalName1,      L"Droid Sans Fallback" },
    { JF_LocalName2,      L"Droid Sans Fallback" },
    { JF_LocalName3,      L"Droid Sans Fallback" },
    { L"System",          L"Droid Sans Fallback" },
    { L"Tahoma",          L"Droid Sans Fallback" },
};

// NtSetDefaultLocale
typedef LONG (WINAPI *NTSETDEFAULTLOCALE)(BOOLEAN, LCID);

void DoSetLocale(BOOLEAN b, LCID lcid, LPCWSTR pszACP, LPCWSTR pszOEMCP)
{
    if (HINSTANCE hNTDLL = LoadLibraryA("ntdll.dll"))
    {
        if (FARPROC fn = GetProcAddress(hNTDLL, "NtSetDefaultLocale"))
        {
            NTSETDEFAULTLOCALE pFN = (NTSETDEFAULTLOCALE)fn;
            (*pFN)(TRUE, lcid);
        }
        FreeLibrary(hNTDLL);
    }

    HKEY hLangKey;
    RegOpenKeyW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\NLS\\CodePage",
                &hLangKey);
    RegSetValueExW(hLangKey, L"ACP", 0, REG_SZ, (BYTE *)pszACP, (wcslen(pszACP) + 1) * sizeof(WCHAR));
    RegSetValueExW(hLangKey, L"OEMCP", 0, REG_SZ, (BYTE *)pszOEMCP, (wcslen(pszOEMCP) + 1) * sizeof(WCHAR));
    RegCloseKey(hLangKey);
}

BOOL DoMakeUserJapanese(HWND hwnd)
{
    WCHAR szPath[MAX_PATH];
    GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath));
    PathRemoveFileSpec(szPath);
    PathAppend(szPath, L"jpn-locale.reg");

    WCHAR szParams[MAX_PATH];
    wsprintf(szParams, L"/s \"%s\"", szPath);
    ShellExecute(hwnd, NULL, L"regedit", szParams, NULL, SW_HIDE);

    LANGID langid = MAKELANGID(LANG_JAPANESE, SUBLANG_DEFAULT);
    LCID lcid = MAKELCID(langid, SORT_DEFAULT);
    DoSetLocale(TRUE, lcid, L"932", L"932");

    MRegKey keyConsole;
    keyConsole.RegOpenKeyEx(HKEY_CURRENT_USER, TEXT("Console"),
        0, KEY_WRITE | KEY_ENUMERATE_SUB_KEYS);
    keyConsole.SetSz(L"FaceName", L"MS Gothic");
    keyConsole.SetDword(L"CodePage", 932);

    for (DWORD dwIndex = 0; ; ++dwIndex)
    {
        WCHAR szName[MAX_PATH];
        DWORD cchName = ARRAYSIZE(szName);
        if (keyConsole.RegEnumKeyEx(dwIndex, szName, &cchName) != ERROR_SUCCESS)
            break;

        MRegKey key;
        key.RegOpenKeyEx(keyConsole, szName, 0, KEY_WRITE);
        key.SetSz(L"FaceName", L"MS Gothic");
        key.SetDword(L"CodePage", 932);
    }

    return TRUE;
}

BOOL DoMakeUserEnglish(HWND hwnd)
{
    WCHAR szPath[MAX_PATH];
    GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath));
    PathRemoveFileSpec(szPath);
    PathAppend(szPath, L"eng-locale.reg");

    WCHAR szParams[MAX_PATH];
    wsprintf(szParams, L"/s \"%s\"", szPath);
    ShellExecute(hwnd, NULL, L"regedit", szParams, NULL, SW_HIDE);

    LANGID langid = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);
    LCID lcid = MAKELCID(langid, SORT_DEFAULT);
    DoSetLocale(TRUE, lcid, L"1252", L"437");

    MRegKey keyConsole;
    keyConsole.RegOpenKeyEx(HKEY_CURRENT_USER, TEXT("Console"),
        0, KEY_WRITE | KEY_ENUMERATE_SUB_KEYS);
    keyConsole.SetSz(L"FaceName", L"VGA");
    keyConsole.SetDword(L"CodePage", 437);

    for (DWORD dwIndex = 0; ; ++dwIndex)
    {
        WCHAR szName[MAX_PATH];
        DWORD cchName = ARRAYSIZE(szName);
        if (keyConsole.RegEnumKeyEx(dwIndex, szName, &cchName) != ERROR_SUCCESS)
            break;

        MRegKey key;
        key.RegOpenKeyEx(keyConsole, szName, 0, KEY_WRITE);
        key.SetSz(L"FaceName", L"VGA");
        key.SetDword(L"CodePage", 437);
    }

    return TRUE;
}

LONG DoSubst(MRegKey& key, const FONTSUBST *subst)
{
    if (subst->to)
        return key.SetSz(subst->from, subst->to);

    return key.RegDeleteValue(subst->from);
}

LONG DoOpenKeyForSubst(MRegKey& key)
{
    return key.RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes"),
        0, KEY_READ | KEY_WRITE);
}

LONG DoSetupSubst(const FONTSUBST *map, size_t count)
{
    MRegKey key;
    LONG nError = DoOpenKeyForSubst(key);
    if (nError)
        return nError;

    for (size_t i = 0; i < count; ++i)
    {
        const FONTSUBST& mapping = map[i];
        LONG nError = DoSubst(key, &mapping);
    }
    return 0;
}

template <size_t t_num>
LONG DoSetupSubst(const FONTSUBST (&map)[t_num])
{
    return DoSetupSubst(&map[0], t_num);
}

INT DoNotepadFont(BOOL bSetup)
{
    MRegKey keyNotepad(HKEY_CURRENT_USER, L"Software\\Microsoft\\Notepad", TRUE);
    if (!keyNotepad)
        return -1;

    if (bSetup)
        keyNotepad.SetSz(L"lfFaceName", JF_LocalName2);
    else
        keyNotepad.SetSz(L"lfFaceName", L"Lucida Console");

    return 0;
}

LPVOID DoGetCustomFont(HINSTANCE hinstData, INT id, DWORD *pcbData)
{
    *pcbData = 0;

    HRSRC hRsrc = FindResource(hinstData,
                               MAKEINTRESOURCE(id),
                               L"CUSTOMFONT");
    if (!hRsrc)
    {
        assert(0);
        return NULL;
    }

    DWORD cbData = SizeofResource(hinstData, hRsrc);
    HGLOBAL hGlobal = LoadResource(hinstData, hRsrc);
    if (!hGlobal)
    {
        assert(0);
        return FALSE;
    }

    if (LPVOID pvData = LockResource(hGlobal))
    {
        *pcbData = cbData;
        return pvData;
    }

    assert(0);
    return NULL;
}

typedef LONG MYERROR;

BOOL EnableProcessPriviledge(LPCTSTR pszSE_)
{
    BOOL f;
    HANDLE hProcess;
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    
    f = FALSE;
    hProcess = GetCurrentProcess();
    if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        if (LookupPrivilegeValue(NULL, pszSE_, &luid))
        {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            tp.Privileges[0].Luid = luid;
            f = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        }
        CloseHandle(hToken);
    }
    return f;
}

BOOL IsUserJapanese(void)
{
    return PRIMARYLANGID(GetUserDefaultLangID()) == LANG_JAPANESE;
}

BOOL IsThereDroidFont(void)
{
    TCHAR szFontFile[MAX_PATH];
    GetWindowsDirectory(szFontFile, MAX_PATH);
    PathAppend(szFontFile, L"Fonts");
    PathAppend(szFontFile, L"DroidSansFallback.ttf");

    return PathFileExists(szFontFile);
}

BOOL DoSetUserKeyboardRegistry(DWORD dwIndex, DWORD dwLangID, DWORD dwLangID2, BOOL bInstall)
{
    WCHAR szPreload[32], szPreload2[32], szIndex[32], szLang[32];
    DWORD cb;

    wsprintfW(szPreload, L"%08lX", dwLangID);
    wsprintfW(szPreload2, L"%08lX", dwLangID2);
    wsprintfW(szIndex, L"%lu", dwIndex);
    wsprintfW(szLang, L"%04lX", dwLangID);

    /* current user */
    {
        MRegKey key;
        if (key.RegOpenKeyExW(HKEY_CURRENT_USER, L"Keyboard Layout\\Preload",
                              0, KEY_WRITE) == ERROR_SUCCESS)
        {
            cb = (lstrlenW(szPreload) + 1) * sizeof(WCHAR);
            RegSetValueExW(key, szIndex, 0, REG_SZ, (LPBYTE)szPreload, cb);

            RegDeleteValueW(key, szPreload2);
        }
    }

    /* default user */
    {
        MRegKey key;
        if (key.RegOpenKeyExW(HKEY_USERS, L".DEFAULT\\Keyboard Layout\\Preload",
                              0, KEY_WRITE) == ERROR_SUCCESS)
        {
            cb = (lstrlenW(szPreload) + 1) * sizeof(WCHAR);
            RegSetValueExW(key, szIndex, 0, REG_SZ, (LPBYTE)szPreload, cb);

            RegDeleteValueW(key, szPreload2);
        }
    }

    /* local machine */
    {
        MRegKey key;
        if (key.RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Nls\\Language",
                              0, KEY_WRITE) == ERROR_SUCCESS)
        {
            cb = (lstrlenW(szLang) + 1) * sizeof(WCHAR);
            RegSetValueExW(key, L"Default", 0, REG_SZ, (LPBYTE)szLang, cb);
            RegSetValueExW(key, L"InstallLanguage", 0, REG_SZ, (LPBYTE)szLang, cb);
        }
    }

#ifndef KLF_UNLOADPREVIOUS
    #define KLF_UNLOADPREVIOUS 4
#endif
    HKL hKL = LoadKeyboardLayoutW(szPreload, KLF_ACTIVATE | KLF_UNLOADPREVIOUS);

    SystemParametersInfoW(SPI_SETDEFAULTINPUTLANG,
                          0,
                          &hKL,
                          0);

    DWORD dwRecipients = BSM_ALLCOMPONENTS;
    BroadcastSystemMessageW(BSF_POSTMESSAGE,
                            &dwRecipients,
                            WM_INPUTLANGCHANGEREQUEST,
                            0,
                            (LPARAM)hKL);

    return TRUE;
}

BOOL DoSetupConsoleFonts(BOOL bInstall)
{
    MRegKey key;
    WCHAR szText[LF_FACESIZE];
    if (key.RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Console\\TrueTypeFont",
                          0, KEY_READ | KEY_WRITE) == ERROR_SUCCESS)
    {
        if (bInstall)
        {
            if (key.QuerySz(L"932", szText, _countof(szText)) == ERROR_SUCCESS)
            {
                if (lstrcmpiW(JF_LocalName2, szText) == 0)
                    ;
                else
                    key.SetSz(L"932.JPN-Package-Save", szText);
            }
            key.SetSz(L"932", JF_LocalName2);
        }
        else
        {
            if (key.QuerySz(L"932.JPN-Package-Save", szText, _countof(szText)) == ERROR_SUCCESS)
            {
                key.SetSz(L"932", szText);
                key.RegDeleteValue(L"932.JPN-Package-Save");
            }
            else
            {
                key.SetSz(L"932", JF_LocalName2);
            }
        }
        return TRUE;
    }

    return FALSE;
}

extern "C"
INT WINAPI
WinMain(HINSTANCE   hInstance,
        HINSTANCE   hPrevInstance,
        LPSTR       lpCmdLine,
        INT         nCmdShow)
{
    // check windows directory
    TCHAR szWinDir[MAX_PATH];
    GetWindowsDirectory(szWinDir, ARRAYSIZE(szWinDir));
    if (wcsstr(szWinDir, L"ReactOS") == NULL)
    {
        MessageBox(NULL, LoadStringDx(102), NULL, MB_ICONERROR);
        return -1;
    }

    if (lstrcmpiA(lpCmdLine, "/i") == 0) // install
    {
        DoSetupSubst(NEU_MapForInstall);
        DoMakeUserJapanese(NULL);
        DoSetupSubst(JPN_MapForInstall);
        DoSetUserKeyboardRegistry(1, 0x411, 0x409, TRUE);

        DoNotepadFont(TRUE);
        DoSetupConsoleFonts(TRUE);

        SendMessage(HWND_BROADCAST, WM_FONTCHANGE, 0, 0);

        return 0;
    }
    else if (lstrcmpiA(lpCmdLine, "/u") == 0) // uninstall
    {
        DoNotepadFont(FALSE);

        if (IsThereDroidFont())
        {
            DoSetupSubst(NEU_MapForUninstallWithDroid);
        }
        else
        {
            DoSetupSubst(NEU_MapForUninstallNoDroid);
        }

        if (IsUserJapanese())
        {
            if (!IsThereDroidFont() ||
                MessageBox(NULL, LoadStringDx(106), LoadStringDx(101),
                           MB_ICONINFORMATION | MB_YESNO) == IDYES)
            {
                DoMakeUserEnglish(NULL);
                DoSetUserKeyboardRegistry(1, 0x409, 0x411, FALSE);
            }
            else
            {
                DoSetupSubst(JPN_MapForUninstallWithDroid);
            }
        }

        DoSetupConsoleFonts(FALSE);

        SendMessage(HWND_BROADCAST, WM_FONTCHANGE, 0, 0);

        return 0;
    }
    else
    {
        return 0;
    }
}
