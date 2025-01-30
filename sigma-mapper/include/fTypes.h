#pragma once

#include <Windows.h>
#include <bit>
#include <filesystem>

constexpr size_t sizePage4K  = 0x1000;
constexpr size_t sizePage2MB = sizePage4K * 512;
constexpr size_t sizePage1GB = sizePage2MB * 512;

class SMART_HANDLE {
   private:
    HANDLE m_handle = INVALID_HANDLE_VALUE;

   public:
    SMART_HANDLE() = default;

    SMART_HANDLE(HANDLE inHandle) : m_handle(inHandle) {}

    SMART_HANDLE(SMART_HANDLE&& other) : m_handle(other.m_handle) { other.m_handle = INVALID_HANDLE_VALUE; }

    ~SMART_HANDLE() { close(); }

    SMART_HANDLE(const SMART_HANDLE&)            = delete;
    SMART_HANDLE& operator=(const SMART_HANDLE&) = delete;

    SMART_HANDLE& operator=(SMART_HANDLE&& other) {
        if (this != &other) {
            close();
            m_handle       = other.m_handle;
            other.m_handle = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    HANDLE get() const { return m_handle; }

    void close() {
        if (m_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_handle);
            m_handle = INVALID_HANDLE_VALUE;
        }
    }

    explicit operator bool() const { return m_handle != INVALID_HANDLE_VALUE; }
    operator HANDLE() const { return m_handle; }
};

class PE_HEADER {
   private:
    uint8_t* m_buffer;

   public:
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NTHeader;
    PIMAGE_FILE_HEADER FileHeader;
    PIMAGE_OPTIONAL_HEADER OptionalHeader;
    PIMAGE_SECTION_HEADER SectionHeader;

    PE_HEADER() = default;

    PE_HEADER(void* inBuffer) : m_buffer(std::bit_cast<uint8_t*>(inBuffer)) {
        DosHeader      = std::bit_cast<PIMAGE_DOS_HEADER>(m_buffer);
        NTHeader       = std::bit_cast<PIMAGE_NT_HEADERS>(m_buffer + DosHeader->e_lfanew);
        FileHeader     = &NTHeader->FileHeader;
        OptionalHeader = &NTHeader->OptionalHeader;
        SectionHeader  = IMAGE_FIRST_SECTION(NTHeader);
    }

    uint8_t* GetBuffer() const { return m_buffer; }

    explicit operator bool() const { return DosHeader && DosHeader->e_magic == IMAGE_DOS_SIGNATURE && NTHeader && NTHeader->Signature == IMAGE_NT_SIGNATURE; }
};
