#include "injection.h"

bool fixImports(const RAWFILE& dll) {
    PIMAGE_IMPORT_DESCRIPTOR importDesc =
        std::bit_cast<PIMAGE_IMPORT_DESCRIPTOR>(dll.fixedBuffer + dll.headers.OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (; importDesc->Name != 0; importDesc++) {
        const char* moduleName = std::bit_cast<const char*>(dll.fixedBuffer + importDesc->Name);
        HMODULE hModule        = LoadLibraryA(moduleName);

        if (!hModule) return false;

        PIMAGE_THUNK_DATA firstThunk    = std::bit_cast<PIMAGE_THUNK_DATA>(dll.fixedBuffer + importDesc->FirstThunk);
        PIMAGE_THUNK_DATA originalThunk = std::bit_cast<PIMAGE_THUNK_DATA>(dll.fixedBuffer + importDesc->OriginalFirstThunk);

        if (!firstThunk && !originalThunk) return false;

        for (; originalThunk->u1.AddressOfData != 0; originalThunk++, firstThunk++) {
            if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal)) {
                const char* ordinal     = std::bit_cast<const char*>(originalThunk->u1.Ordinal & 0xffff);
                firstThunk->u1.Function = std::bit_cast<ULONGLONG>(GetProcAddress(hModule, ordinal));
            } else {
                PIMAGE_IMPORT_BY_NAME function = std::bit_cast<PIMAGE_IMPORT_BY_NAME>(dll.fixedBuffer + originalThunk->u1.AddressOfData);
                firstThunk->u1.Function        = std::bit_cast<ULONGLONG>(GetProcAddress(hModule, function->Name));
            }
        }
    }
}

void METHOD::manualMap(const TARGETPROC& process, const RAWFILE& dll) {
    console->log(LogLevel::orange, "[MANUAL MAP]\n\n");

    std::memcpy(dll.fixedBuffer, dll.rawBuffer, dll.headers.OptionalHeader->SizeOfHeaders);

    console->report(LogLevel::success, "mapped headers\n\n");

    for (WORD i = 0; i < dll.headers.FileHeader->NumberOfSections; i++) {
        void* destination     = dll.fixedBuffer + dll.headers.SectionHeader[i].VirtualAddress;
        uint8_t* sectionToMap = dll.rawBuffer + dll.headers.SectionHeader[i].PointerToRawData;
        size_t sizeToMap      = dll.headers.SectionHeader[i].SizeOfRawData;

        std::memcpy(destination, sectionToMap, sizeToMap);

        console->report(LogLevel::success, "mapped section %s\n", dll.headers.SectionHeader[i].Name);
        console->log("    raw addr -> 0x%X\n", dll.headers.SectionHeader[i].PointerToRawData);
        console->log("    addr -> 0x%X\n", destination);
        console->log("    size -> 0x%X\n\n", sizeToMap);
    }

    system("pause");
    fixImports(dll);
}
