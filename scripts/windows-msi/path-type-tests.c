#include <stdio.h>
#include "path-type.h"

#define CHECK(expression) do { if (!(expression)) { printf("FAIL line %d\n", __LINE__); return 1; } } while (0)

static int preserves_bytes(HKEY key, DWORD before, DWORD wanted, LPCWSTR text)
{
    WCHAR buffer[256];
    DWORD type = 0, bytes = sizeof(buffer);
    CHECK(RegSetValueExW(key, L"Path", 0, before, (const BYTE *)text, (DWORD)((lstrlenW(text) + 1) * sizeof(WCHAR))) == ERROR_SUCCESS);
    CHECK(depscan_restore_type(key, L"Path", wanted) == ERROR_SUCCESS);
    CHECK(RegQueryValueExW(key, L"Path", NULL, &type, (BYTE *)buffer, &bytes) == ERROR_SUCCESS);
    CHECK(type == wanted);
    CHECK(bytes == (lstrlenW(text) + 1) * sizeof(WCHAR));
    CHECK(lstrcmpW(buffer, text) == 0);
    return 0;
}

int wmain(void)
{
    HKEY key;
    WCHAR name[128];
    DWORD disposition, value = 42, type = 0, bytes = sizeof(value);
    int failed = 0;
    swprintf_s(name, ARRAYSIZE(name), L"Software\\DepScanMsiTests-%lu-%llu", GetCurrentProcessId(), GetTickCount64());
    CHECK(RegCreateKeyExW(HKEY_CURRENT_USER, name, 0, NULL, REG_OPTION_VOLATILE,
        KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &key, &disposition) == ERROR_SUCCESS);
    CHECK(disposition == REG_CREATED_NEW_KEY);
    failed |= preserves_bytes(key, REG_SZ, REG_EXPAND_SZ, L"C:\\Windows;C:\\Program Files\\Existing");
    failed |= preserves_bytes(key, REG_SZ, REG_EXPAND_SZ, L"%SystemRoot%\\System32;;C:\\Unrelated;C:\\Added later;");
    failed |= preserves_bytes(key, REG_EXPAND_SZ, REG_SZ, L"C:\\Windows;literal %TOKEN%;C:\\Unrelated");
    failed |= preserves_bytes(key, REG_SZ, REG_SZ, L"");
    failed |= preserves_bytes(key, REG_SZ, REG_EXPAND_SZ, L"C:\\Users\\\u03bb;C:\\Program Files\\Existing");
    if (depscan_restore_type(key, L"Path", REG_NONE) != ERROR_SUCCESS)
        failed = 1;
    if (RegDeleteValueW(key, L"Path") != ERROR_SUCCESS ||
        depscan_restore_type(key, L"Path", REG_EXPAND_SZ) != ERROR_SUCCESS ||
        RegQueryValueExW(key, L"Path", NULL, NULL, NULL, NULL) != ERROR_FILE_NOT_FOUND)
        failed = 1;
    if (RegSetValueExW(key, L"Path", 0, REG_DWORD, (const BYTE *)&value, sizeof(value)) != ERROR_SUCCESS ||
        depscan_restore_type(key, L"Path", REG_EXPAND_SZ) != ERROR_INVALID_DATA ||
        depscan_restore_type(key, L"Path", REG_BINARY) != ERROR_INVALID_PARAMETER ||
        RegQueryValueExW(key, L"Path", NULL, &type, (BYTE *)&value, &bytes) != ERROR_SUCCESS ||
        type != REG_DWORD || value != 42)
        failed = 1;
    if (RegSetValueExW(key, L"Path", 0, REG_SZ, (const BYTE *)L"bad", 3) != ERROR_SUCCESS ||
        depscan_restore_type(key, L"Path", REG_EXPAND_SZ) != ERROR_INVALID_DATA)
        failed = 1;
    RegCloseKey(key);
    if (RegDeleteKeyW(HKEY_CURRENT_USER, name) != ERROR_SUCCESS)
        failed = 1;
    if (!failed)
        puts("PATH registry type tests passed: raw bytes, both kinds, expansion references, missing and invalid values");
    return failed;
}
