#include "path-type.h"
#include <msi.h>
#include <msiquery.h>

static const WCHAR environment_key[] =
    L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";

static UINT report_status(MSIHANDLE installer, LSTATUS status)
{
    MSIHANDLE record;
    if (status == ERROR_SUCCESS)
        return ERROR_SUCCESS;
    record = MsiCreateRecord(1);
    if (record != 0) {
        MsiRecordSetStringW(record, 0, L"DepScan could not preserve the machine PATH registry type (error [1]).");
        MsiRecordSetInteger(record, 1, status);
        MsiProcessMessage(installer, INSTALLMESSAGE_ERROR, record);
        MsiCloseHandle(record);
    }
    return ERROR_INSTALL_FAILURE;
}

__declspec(dllexport) UINT __stdcall CapturePathType(MSIHANDLE installer)
{
    HKEY key;
    DWORD type = REG_NONE;
    WCHAR data[2];
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, environment_key, 0, KEY_QUERY_VALUE, &key);
    if (status == ERROR_SUCCESS) {
        status = RegQueryValueExW(key, L"Path", NULL, &type, NULL, NULL);
        RegCloseKey(key);
    }
    if (status == ERROR_FILE_NOT_FOUND) {
        type = REG_NONE;
        status = ERROR_SUCCESS;
    } else if (status == ERROR_SUCCESS && type != REG_SZ && type != REG_EXPAND_SZ) {
        return report_status(installer, ERROR_INVALID_DATA);
    }
    if (status != ERROR_SUCCESS)
        return report_status(installer, status);
    data[0] = (WCHAR)(L'0' + type);
    data[1] = L'\0';
    status = MsiSetPropertyW(installer, L"DepscanRestorePathType", data);
    if (status == ERROR_SUCCESS)
        status = MsiSetPropertyW(installer, L"DepscanRollbackPathType", data);
    return report_status(installer, status);
}

__declspec(dllexport) UINT __stdcall RestorePathType(MSIHANDLE installer)
{
    HKEY key;
    WCHAR data[3] = {0};
    DWORD size = ARRAYSIZE(data);
    LSTATUS status = MsiGetPropertyW(installer, L"CustomActionData", data, &size);
    if (status != ERROR_SUCCESS || size != 1 || data[0] < L'0' || data[0] > L'2')
        return report_status(installer, ERROR_INVALID_DATA);
    /* Only this fixed machine value is writable; no property supplies a key or text. */
    status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, environment_key, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key);
    if (status == ERROR_FILE_NOT_FOUND)
        return ERROR_SUCCESS;
    if (status == ERROR_SUCCESS) {
        status = depscan_restore_type(key, L"Path", (DWORD)(data[0] - L'0'));
        RegCloseKey(key);
    }
    return report_status(installer, status);
}
