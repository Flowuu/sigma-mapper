#include "injection.h"

bool fixBaseReloc(const TARGETPROC& process, const RAWFILE& dll) {
    // reloc directory table
    PIMAGE_BASE_RELOCATION baseReloc =
        std::bit_cast<PIMAGE_BASE_RELOCATION>(dll.fixedBuffer + dll.headers.OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    // calculate base delta
    ULONGLONG relocationOffset;
    if (std::bit_cast<ULONGLONG>(process.remoteBuffer) > dll.headers.OptionalHeader->ImageBase)
        relocationOffset = std::bit_cast<ULONGLONG>(process.remoteBuffer) - dll.headers.OptionalHeader->ImageBase;
    else
        relocationOffset = dll.headers.OptionalHeader->ImageBase - std::bit_cast<ULONGLONG>(process.remoteBuffer);

    // loop each baseReloc block
    for (; baseReloc->VirtualAddress != 0; baseReloc += baseReloc->SizeOfBlock) {
        // get number of entries inside baseReloc block
        unsigned long long entryNum = (baseReloc->SizeOfBlock - sizeof(PIMAGE_BASE_RELOCATION)) / sizeof(WORD);

        // current entry ptr
        WORD* entry = std::bit_cast<WORD*>(baseReloc);

        // loop each entry
        for (unsigned long long i = 0; i < entryNum; i++) {
            // check relocation type
            if (entry[i] >> 0x0C == IMAGE_REL_BASED_DIR64) {
                uintptr_t* address = std::bit_cast<uintptr_t*>(dll.fixedBuffer + baseReloc->VirtualAddress + (entry[i] & 0xFFF));

                // fix address
                *address += relocationOffset;
            }
        }
    }

    return true;
}

bool getImports(const RAWFILE& dll) {
    // get import directory table
    PIMAGE_IMPORT_DESCRIPTOR importDesc =
        std::bit_cast<PIMAGE_IMPORT_DESCRIPTOR>(dll.fixedBuffer + dll.headers.OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    if (importDesc->Name == 0) return false;

    // loop through module/dll's descriptor
    for (; importDesc->Name != 0; importDesc++) {
        // get module/dll name
        const char* moduleName = std::bit_cast<const char*>(dll.fixedBuffer + importDesc->Name);
        HMODULE hModule        = LoadLibraryA(moduleName);
        console->log(LogLevel::lightcyan, "[%s]\n", moduleName);

        if (!hModule) return false;

        // address of function
        PIMAGE_THUNK_DATA firstThunk = std::bit_cast<PIMAGE_THUNK_DATA>(dll.fixedBuffer + importDesc->FirstThunk);

        // address of function name/ordinal
        PIMAGE_THUNK_DATA originalThunk = std::bit_cast<PIMAGE_THUNK_DATA>(dll.fixedBuffer + importDesc->OriginalFirstThunk);

        if (!firstThunk && !originalThunk) return false;

        for (; originalThunk->u1.AddressOfData != 0; originalThunk++, firstThunk++) {
            // if ordinal
            if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal)) {
                // get ordinal name
                const char* ordinal = std::bit_cast<const char*>(originalThunk->u1.Ordinal & 0xffff);

                // map address of function
                firstThunk->u1.Function = std::bit_cast<ULONGLONG>(GetProcAddress(hModule, ordinal));
                console->log("    imported %s by ordinal -> 0x%X\n", ordinal, firstThunk->u1.Function);

            } else {
                // get function name
                PIMAGE_IMPORT_BY_NAME function = std::bit_cast<PIMAGE_IMPORT_BY_NAME>(dll.fixedBuffer + originalThunk->u1.AddressOfData);

                // map address of function
                firstThunk->u1.Function = std::bit_cast<ULONGLONG>(GetProcAddress(hModule, function->Name));
                console->log("    imported %s by name -> 0x%X\n", function->Name, firstThunk->u1.Function);
            }
        }
        console->log("\n");
    }

    return true;
}

void METHOD::manualMap(const TARGETPROC& process, const RAWFILE& dll) {
    console->log(LogLevel::orange, "[MANUAL MAP]\n");

    // map the header of dll localy
    std::memcpy(dll.fixedBuffer, dll.rawBuffer, dll.headers.OptionalHeader->SizeOfHeaders);

    console->report(LogLevel::success, "mapped headers\n\n");

    // map the sections of dll localy
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

    // call getImports()
    if (!getImports(dll)) {
        console->report(LogLevel::error, "failed to get imports\n\n");
        return;
    }

    // call fixBaseReloc()
    if (!fixBaseReloc(process, dll)) {
        console->report(LogLevel::error, "failed to fix base reloc\n\n");
        return;
    }

    // write the fixed image to target
    if (!WriteProcessMemory(process.handle, process.remoteBuffer, dll.fixedBuffer, dll.headers.OptionalHeader->SizeOfImage, nullptr)) {
        console->report(LogLevel::error, "failed to write fixed image on target proc\n\n");
        return;
    }

    ENTRYPARAM param;
    param.base     = std::bit_cast<HINSTANCE>(process.remoteBuffer);
    param.reason   = DLL_PROCESS_ATTACH;
    param.reserved = nullptr;

    if (!WriteProcessMemory(process.handle, process.pEntryParam, &param, sizeof(ENTRYPARAM), nullptr)) {
        console->report(LogLevel::error, "failed to write param on target proc\n\n");
        return;
    }

    DLLENTRY entry = std::bit_cast<DLLENTRY>(process.remoteBuffer + dll.headers.OptionalHeader->AddressOfEntryPoint);

    SMART_HANDLE hThread = CreateRemoteThread(process.handle, nullptr, 0, std::bit_cast<LPTHREAD_START_ROUTINE>(entry), process.pEntryParam, 0, nullptr);

    WaitForSingleObject(hThread, INFINITE);

    console->report(LogLevel::success, "injected\n\n");
}
