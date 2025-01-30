#include "injection.h"

void METHOD::loadLib(const TARGETPROC& process, const RAWFILE& dll) {
    if (!WriteProcessMemory(process.handle, process.remoteBuffer, std::string(dll.path.string() + "\0").c_str(), dll.path.string().length() + 0x1, nullptr)) {
        console->report(LogLevel::error, "failed to write file path\n");
        return;
    }

    SMART_HANDLE hExecute = CreateRemoteThread(process.handle, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), process.remoteBuffer, 0, nullptr);
    WaitForSingleObject(hExecute, INFINITE);
}
