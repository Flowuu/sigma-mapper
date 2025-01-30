#pragma once
#include "../../include/fTil.hpp"
#include "../../include/fLogger.hpp"

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

class TARGETPROC {};
