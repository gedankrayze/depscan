#ifndef DEPSCAN_PATH_TYPE_H
#define DEPSCAN_PATH_TYPE_H
#include <windows.h>

/* REG_NONE means the value did not exist before the MSI transaction. */
LSTATUS depscan_restore_type(HKEY key, LPCWSTR name, DWORD original_type);
#endif
