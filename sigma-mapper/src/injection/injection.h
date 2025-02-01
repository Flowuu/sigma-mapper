#pragma once
#include "../../include/fTil.hpp"
#include "../../include/fLogger.hpp"

enum class INJMETHOD : unsigned int { NONE, LOADLIBRARY, MANUALMAP };

using DLLENTRY = BOOL(__stdcall*)(HINSTANCE, DWORD, LPVOID);

struct CALLPARAM {
    HINSTANCE base;
    DWORD reason;
    LPVOID reserved;

    DLLENTRY entry;
};

class RAWFILE {
   public:
    std::string fileName;
    std::filesystem::path path;
    size_t size;

    uint8_t* rawBuffer;
    uint8_t* fixedBuffer;
    PE_HEADER headers;

    RAWFILE() = default;

    RAWFILE(std::filesystem::path inPath) : fileName(""), path(inPath), rawBuffer(nullptr), size(0) {
        fileName           = path.filename().string();
        SMART_HANDLE hFile = CreateFileA(path.string().c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (!hFile) return;

        size = GetFileSize(hFile, nullptr);
        if (!size) return;

        rawBuffer = static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!rawBuffer) return;

        if (!ReadFile(hFile, rawBuffer, static_cast<DWORD>(size), nullptr, nullptr)) return;

        headers = rawBuffer;
        if (!headers) return;

        fixedBuffer = static_cast<uint8_t*>(VirtualAlloc(nullptr, headers.OptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!rawBuffer) return;
    }

    ~RAWFILE() {
        if (rawBuffer != nullptr) VirtualFree(rawBuffer, 0, MEM_RELEASE);
        if (fixedBuffer != nullptr) VirtualFree(fixedBuffer, 0, MEM_RELEASE);
    }

    explicit operator bool() const { return size > 0 && rawBuffer != nullptr && headers; }
};

class TARGETPROC {
   public:
    std::string name;
    DWORD pId;
    SMART_HANDLE handle;

    uint8_t* remoteBuffer;
    void* pCallParam;
    void* pRemoteCall;

    INJMETHOD method;

    TARGETPROC(const std::string& procName, const RAWFILE& file, const INJMETHOD& inMethod) : name(procName), method(inMethod) {
        pId = util->getPId(name.c_str());
        if (!pId) return;

        handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pId);
        if (!handle) return;

        remoteBuffer = std::bit_cast<uint8_t*>(
            VirtualAllocEx(handle, nullptr, file.headers.OptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!remoteBuffer) return;

        if (method == INJMETHOD::MANUALMAP) {
            pCallParam = std::bit_cast<uint8_t*>(VirtualAllocEx(handle, nullptr, sizeof(CALLPARAM), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
            if (!pCallParam) return;

            pRemoteCall = std::bit_cast<uint8_t*>(VirtualAllocEx(handle, nullptr, sizePage4K, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
            if (!pCallParam) return;
        }
    }

    ~TARGETPROC() { /*VirtualFreeEx(handle, remoteBuffer, 0, MEM_RELEASE);*/
        if (method == INJMETHOD::MANUALMAP || pCallParam != nullptr || pRemoteCall != nullptr) {
            VirtualFreeEx(handle, pCallParam, 0, MEM_RELEASE);
            VirtualFreeEx(handle, pRemoteCall, 0, MEM_RELEASE);
        }
    }

    explicit operator bool() const {
        if (method == INJMETHOD::MANUALMAP)
            return handle && pId > 0 && remoteBuffer != nullptr && pCallParam != nullptr && pRemoteCall != nullptr;
        else
            return handle && pId > 0 && remoteBuffer != nullptr;
    }
};

struct METHOD {
    static void loadLib(const TARGETPROC& process, const RAWFILE& dll);
    static void manualMap(const TARGETPROC& process, const RAWFILE& dll);
};
