#pragma once
#include "../../include/fTil.hpp"
#include "../../include/fLogger.hpp"

struct MAPPARAM {
    uint8_t* buffer;
    decltype(&LoadLibraryA) LoadLibraryAFunc;
    decltype(&GetProcAddress) GetProcAddressFunc;
};

class RAWFILE {
   private:
    void* buffer;

   public:
    std::string fileName;
    std::filesystem::path path;
    size_t size;

    PE_HEADER headers;

    RAWFILE() = default;

    RAWFILE(std::filesystem::path inPath) : fileName(""), path(inPath), buffer(nullptr), size(0) {
        fileName           = path.filename().string();
        SMART_HANDLE hFile = CreateFileA(path.string().c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (!hFile) return;

        size = GetFileSize(hFile, nullptr);
        if (!size) return;

        buffer = malloc(size);
        if (!buffer) return;

        if (!ReadFile(hFile, buffer, static_cast<DWORD>(size), nullptr, nullptr)) return;

        headers = buffer;
        if (!headers) return;
    }

    ~RAWFILE() { free(buffer); }

    explicit operator bool() const { return size > 0 && buffer != nullptr && headers; }
};

class TARGETPROC {
   private:
    SMART_HANDLE handle;

   public:
    std::string name;
    DWORD pId;

    uint8_t* remoteBuffer;
    void* remoteParam;
    void* remoteFunc;

    TARGETPROC(const std::string& procName, const RAWFILE& file) : name(procName) {
        pId = util->getPId(name.c_str());
        if (!pId) return;

        handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pId);
        if (!handle) return;

        remoteBuffer = std::bit_cast<uint8_t*>(VirtualAllocEx(handle, nullptr, file.size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!remoteBuffer) return;

        remoteParam = VirtualAllocEx(handle, nullptr, sizeof(MAPPARAM), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteParam) return;

        remoteFunc = VirtualAllocEx(handle, nullptr, sizePage4K, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteFunc) return;
    }

    ~TARGETPROC() {
        VirtualFreeEx(handle, remoteBuffer, 0, MEM_RELEASE);
        VirtualFreeEx(handle, remoteParam, 0, MEM_RELEASE);
        VirtualFreeEx(handle, remoteFunc, 0, MEM_RELEASE);
    }

    explicit operator bool() const { return handle && pId > 0 && remoteBuffer != nullptr && remoteParam != nullptr && remoteFunc != nullptr; }
};

struct METHOD {
    static void manualMap();
};
