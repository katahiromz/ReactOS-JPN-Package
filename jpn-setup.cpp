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
};

static const FONTSUBST JPN_MapForInstall[] =
{
    { JF_LocalName0,      NULL },
    { JF_LocalName2,      NULL },
    { JF_LocalName1,      NULL },
    { JF_LocalName3,      NULL },
};

static const FONTSUBST NEU_MapForUninstallNoDroid[] =
{
    { L"MS UI Gothic",    NULL },
    { L"MS Mincho",       NULL },
    { L"MS PMincho",      NULL },
    { L"MS Gothic",       NULL },
    { L"MS PGothic",      NULL },
};

static const FONTSUBST JPN_MapForUninstallNoDroid[] =
{
    { JF_LocalName0,      NULL },
    { JF_LocalName1,      NULL },
    { JF_LocalName2,      NULL },
    { JF_LocalName3,      NULL },
};

static const FONTSUBST NEU_MapForUninstallWithDroid[] =
{
    { L"MS UI Gothic",    L"Droid Sans Fallback" },
    { L"MS Mincho",       L"Droid Sans Fallback" },
    { L"MS PMincho",      L"Droid Sans Fallback" },
    { L"MS Gothic",       L"Droid Sans Fallback" },
    { L"MS PGothic",      L"Droid Sans Fallback" },
};

static const FONTSUBST JPN_MapForUninstallWithDroid[] =
{
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

LPVOID DoGetCustomFont(INT id, DWORD *pcbData)
{
    *pcbData = 0;

    HMODULE hMod = GetModuleHandle(NULL);
    HRSRC hRsrc = FindResource(hMod,
                               MAKEINTRESOURCE(id),
                               L"CUSTOMFONT");
    if (!hRsrc)
    {
        assert(0);
        return NULL;
    }

    DWORD cbData = SizeofResource(hMod, hRsrc);
    HGLOBAL hGlobal = LoadResource(hMod, hRsrc);
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

MYERROR DoInstallFont(LPCWSTR pszFileName, LPCWSTR pszEntry, INT id, BOOL bInstall)
{
    MRegKey keyFonts;

    LONG n = keyFonts.RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                                   L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts",
                                   0,
                                   KEY_WRITE);
    if (n)
    {
        assert(0);
        return FALSE;
    }

    TCHAR szFontFile[MAX_PATH];
    GetWindowsDirectory(szFontFile, MAX_PATH);
    PathAppend(szFontFile, L"Fonts");
    PathAppend(szFontFile, pszFileName);

    TCHAR szEntry[MAX_PATH];
    lstrcpy(szEntry, pszEntry);
    lstrcat(szEntry, L" (TrueType)");

    if (bInstall)
    {
        RemoveFontResource(pszFileName);
        keyFonts.RegDeleteValue(szEntry);

        DWORD cbData = 0;
        LPVOID pvData = DoGetCustomFont(id, &cbData);
        if (!pvData || !cbData)
        {
            assert(0);
            return 1;
        }

        TCHAR szPath[MAX_PATH];
        GetTempPath(MAX_PATH, szPath);
        PathAppend(szPath, L"ReactOS-JPN-Setup.tmp");

        FILE *fp = _wfopen(szPath, L"wb");
        if (!fp)
        {
            assert(0);
            return 2;
        }

        int b = fwrite(pvData, cbData, 1, fp);
        fclose(fp);

        if (!b)
        {
            assert(0);
            return 3;
        }

        if (!CopyFile(szPath, szFontFile, FALSE))
        {
            assert(0);
            return 4;
        }

        DeleteFile(szPath);

        if (LONG err = keyFonts.SetSz(szEntry, pszFileName))
        {
            assert(0);
            return 5;
        }

        if (!AddFontResource(pszFileName))
        {
            assert(0);
            return 6;
        }

        return 0;
    }
    else
    {
        RemoveFontResource(pszFileName);
        keyFonts.RegDeleteValue(szEntry);
        DeleteFile(szFontFile);
        return 0;
    }
}

MYERROR DoInstallFonts(BOOL bInstall)
{
    MYERROR err;
    err = DoInstallFont(L"msgothic.ttc", L"MS Gothic & MS PGothic", 100, bInstall);
    if (err)
        return err;

    err = DoInstallFont(L"msmincho.ttc", L"MS Mincho & MS PMincho", 101, bInstall);
    if (err)
        return err;

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

    if (lstrcmpiA(lpCmdLine, "/i") == 0)
    {
        // install
        if (MYERROR err = DoInstallFonts(TRUE))
        {
            TCHAR szText[MAX_PATH * 2];
            wsprintf(szText, LoadStringDx(103), err);
            MessageBox(NULL, szText, NULL, MB_ICONERROR);
            return -1;
        }

        DoSetupSubst(NEU_MapForInstall);
        if (IsUserJapanese())
        {
            DoSetupSubst(JPN_MapForInstall);
        }
        DoNotepadFont(TRUE);
        SendMessage(HWND_BROADCAST, WM_FONTCHANGE, 0, 0);

        return 0;
    }
    else if (lstrcmpiA(lpCmdLine, "/u") == 0)
    {
        // uninstall
        if (MYERROR err = DoInstallFonts(FALSE))
        {
            TCHAR szText[MAX_PATH * 2];
            wsprintf(szText, LoadStringDx(103), err);
            MessageBox(NULL, szText, NULL, MB_ICONERROR);
            return -1;
        }

        if (IsThereDroidFont())
        {
            DoSetupSubst(NEU_MapForUninstallWithDroid);
            if (IsUserJapanese())
            {
                DoSetupSubst(JPN_MapForUninstallWithDroid);
            }
        }
        else
        {
            DoSetupSubst(NEU_MapForUninstallNoDroid);
            if (IsUserJapanese())
            {
                DoSetupSubst(JPN_MapForUninstallNoDroid);
            }
        }

        DoNotepadFont(FALSE);
        SendMessage(HWND_BROADCAST, WM_FONTCHANGE, 0, 0);

        return 0;
    }
    else
    {
        return 0;
    }
}
