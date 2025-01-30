#pragma once

#include "fTypes.h"
#include <memory>
#include <TlHelp32.h>

struct FTIL {
    DWORD getPId(const char* procName) {
        PROCESSENTRY32 procEntry = {sizeof(PROCESSENTRY32)};
        SMART_HANDLE hSnap       = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);

        if (Process32First(hSnap, &procEntry)) {
            do {
                if (!strcmp(procEntry.szExeFile, procName)) return procEntry.th32ProcessID;

            } while (Process32Next(hSnap, &procEntry));
        }
    }
};
inline FTIL* util;
