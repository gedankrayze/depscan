#include "path-type.h"

LSTATUS depscan_restore_type(HKEY key, LPCWSTR name, DWORD original_type)
{
    DWORD type = 0, bytes = 0;
    BYTE *value;
    LSTATUS status;

    if (original_type != REG_NONE && original_type != REG_SZ && original_type != REG_EXPAND_SZ)
        return ERROR_INVALID_PARAMETER;
    if (original_type == REG_NONE)
        return ERROR_SUCCESS;
    status = RegQueryValueExW(key, name, NULL, &type, NULL, &bytes);
    /* Uninstall may legitimately remove a value that contained only our entry. */
    if (status == ERROR_FILE_NOT_FOUND || (status == ERROR_SUCCESS && type == original_type))
        return ERROR_SUCCESS;
    if (status != ERROR_SUCCESS)
        return status;
    if ((type != REG_SZ && type != REG_EXPAND_SZ) || bytes < sizeof(WCHAR) ||
        bytes % sizeof(WCHAR) != 0 || bytes > 1024 * 1024)
        return ERROR_INVALID_DATA;
    value = HeapAlloc(GetProcessHeap(), 0, bytes);
    if (value == NULL)
        return ERROR_OUTOFMEMORY;
    status = RegQueryValueExW(key, name, NULL, &type, value, &bytes);
    if (status == ERROR_SUCCESS) {
        if ((type != REG_SZ && type != REG_EXPAND_SZ) || bytes < sizeof(WCHAR) ||
            bytes % sizeof(WCHAR) != 0 || ((WCHAR *)value)[bytes / sizeof(WCHAR) - 1] != L'\0')
            status = ERROR_INVALID_DATA;
        else
            /* Preserve the current raw bytes, never a saved PATH snapshot. */
            status = RegSetValueExW(key, name, 0, original_type, value, bytes);
    }
    HeapFree(GetProcessHeap(), 0, value);
    return status;
}
