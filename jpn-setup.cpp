// ReactOS Japanese Package
// Copyright (C) 2019 Katayama Hirofumi MZ.
// This file is public domain software.
#include "MRegKey.hpp"

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

static const FONTSUBST JPN_MapForInstall[] =
{
    { L"MS Mincho",       NULL },
    { L"MS Gothic",       NULL },
    { L"MS PMincho",      NULL },
    { L"MS PGothic",      NULL },
    { JF_LocalName0,      NULL },
    { JF_LocalName2,      NULL },
    { JF_LocalName1,      NULL },
    { JF_LocalName3,      NULL },
};

static const FONTSUBST JPN_MapForUninstall[] =
{
    { L"MS UI Gothic",    L"Droid Sans Fallback" },
    { L"MS Mincho",       L"Droid Sans Fallback" },
    { L"MS PMincho",      L"Droid Sans Fallback" },
    { L"MS Gothic",       L"Droid Sans Fallback" },
    { L"MS PGothic",      L"Droid Sans Fallback" },
    { JF_LocalName0,      L"Droid Sans Fallback" },
    { JF_LocalName1,      L"Droid Sans Fallback" },
    { JF_LocalName2,      L"Droid Sans Fallback" },
    { JF_LocalName3,      L"Droid Sans Fallback" },
};

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

INT DoInstallFonts(BOOL bInstall)
{
    if (bInstall)
    {
        AddFontResourceW(L"msgothic.ttc");
        AddFontResourceW(L"msmincho.ttc");
    }
    else
    {
        RemoveFontResourceW(L"msgothic.ttc");
        RemoveFontResourceW(L"msmincho.ttc");
    }
    return 0;
}

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

    if (lstrcmpiA(lpCmdLine, "-i") == 0)
    {
        // install
        DoInstallFonts(TRUE);
        DoSetupSubst(JPN_MapForInstall, ARRAYSIZE(JPN_MapForInstall));
        DoNotepadFont(TRUE);
    }
    else if (lstrcmpiA(lpCmdLine, "-u") == 0)
    {
        // uninstall
        DoInstallFonts(FALSE);
        DoSetupSubst(JPN_MapForUninstall, ARRAYSIZE(JPN_MapForUninstall));
        DoNotepadFont(FALSE);
    }
    else
    {
        return -1;
    }

    return 0;
}
