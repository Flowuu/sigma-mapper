#include "injection.h"

void METHOD::manualMap(const TARGETPROC& process, const RAWFILE& dll) {
    console->log(LogLevel::orange, "[MANUAL MAP]\n\n");

    if (!WriteProcessMemory(process.handle, process.remoteBuffer, dll.buffer, dll.headers.OptionalHeader->SizeOfHeaders, nullptr)) {
        console->report(LogLevel::error, "failed to map headers\n");
        return;
    }

    console->report(LogLevel::success, "map headers\n");
    console->log("    addr -> 0x%X\n", process.remoteBuffer);
    console->log("    size -> 0x%X\n\n", dll.headers.OptionalHeader->SizeOfHeaders);
}
