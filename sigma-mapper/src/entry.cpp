#pragma once

#include <Windows.h>
#include <memory>
#include <TlHelp32.h>

struct SMART_HANDLE {
   private:
    HANDLE m_handle = INVALID_HANDLE_VALUE;

   public:
    SMART_HANDLE() = default;

    SMART_HANDLE(HANDLE inHandle) : m_handle(inHandle) {}

    SMART_HANDLE(SMART_HANDLE&& other) noexcept : m_handle(other.m_handle) { other.m_handle = INVALID_HANDLE_VALUE; }

    ~SMART_HANDLE() { close(); }

    SMART_HANDLE(const SMART_HANDLE&)            = delete;
    SMART_HANDLE& operator=(const SMART_HANDLE&) = delete;

    SMART_HANDLE& operator=(SMART_HANDLE&& other) noexcept {
        if (this != &other) {
            close();
            m_handle       = other.m_handle;
            other.m_handle = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    HANDLE get() const noexcept { return m_handle; }

    void close() {
        if (m_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_handle);
            m_handle = INVALID_HANDLE_VALUE;
        }
    }

    explicit operator bool() const noexcept { return m_handle != INVALID_HANDLE_VALUE; }
    explicit operator HANDLE() const { return m_handle; }
};
