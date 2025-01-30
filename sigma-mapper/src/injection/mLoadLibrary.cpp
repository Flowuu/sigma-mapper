#include "injection.h"

void METHOD::loadLib(const TARGETPROC& process, const RAWFILE& dll) {
    console->log(LogLevel::orange, "[LOAD LIBRARY]\n\n");

    if (!WriteProcessMemory(process.handle, process.remoteBuffer, std::string(dll.path.string() + "\0").c_str(), dll.path.string().length() + 0x1, nullptr)) {
        console->report(LogLevel::error, "failed to write file path\n");
        return;
    }

    console->report(LogLevel::success, "written dll path\n");
    console->log("    addr -> 0x%X\n", process.remoteBuffer);
    console->log("    size -> 0x%X\n\n", dll.path.string().length() + 0x1);

    SMART_HANDLE hExecute = CreateRemoteThread(process.handle, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), process.remoteBuffer, 0, nullptr);
    WaitForSingleObject(hExecute, INFINITE);

    console->report(LogLevel::success, "injected\n\n");
}
