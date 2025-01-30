#include "injection/injection.h"

int main(int argc, char** argv) {
    console->clear();
    console->log(LogLevel::orange, "[sigma mapper]\n\n");

    INJMETHOD method = INJMETHOD::NONE;
    std::string filePath;
    std::string procName;

    if (argc == 1) {
        procName = console->getInput<std::string>("process -> ");
        filePath = console->getInput<std::string>("file path -> ");

    } else if (argc == 2) {
        filePath = argv[1];
        procName = console->getInput<std::string>("process -> ");

    } else if (argc == 3) {
        filePath = argv[1];
        procName = argv[2];

    } else {
        console->report(LogLevel::error, "usage: %s <dll path> <process name>\n", argv[0]);
        return 1;
    }

    RAWFILE dll(filePath);
    if (!dll) {
        console->report(LogLevel::error, "RAWFILE: %s\n", console->getLastError().c_str());
        return 1;
    }

    TARGETPROC process(procName, dll);
    if (!process) {
        console->report(LogLevel::error, "TARGETPROC: %s\n", console->getLastError().c_str());
        return 1;
    }

    method = static_cast<INJMETHOD>(console->getInput<unsigned int>("loadlibrary: 1 | manual map: 2\n"));

    if (method != INJMETHOD::LOADLIBRARY && method != INJMETHOD::MANUALMAP) {
        console->report(LogLevel::error, "invalid method\n", argv[0]);
        return 1;
    }

    console->log(LogLevel::lightcyan, "[process info]\n");
    console->log("name -> %s\n", process.name.c_str());
    console->log("id   -> %d\n", static_cast<int>(process.pId));
    console->log("remote buffer ptr -> 0x%X\n", process.remoteBuffer);
    console->log("remote param ptr  -> 0x%X\n", process.remoteParam);
    console->log("remote func ptr   -> 0x%X\n\n", process.remoteFunc);

    console->log(LogLevel::lightcyan, "[file info]\n");
    console->log("name -> %s\n", dll.fileName.c_str());
    console->log("size -> %d KB\n", dll.size / 1000);
    console->log("architecture -> %s\n\n", dll.headers.FileHeader->Machine == IMAGE_FILE_MACHINE_AMD64 ? "x64" : "x32");

    switch (method) {
        case INJMETHOD::LOADLIBRARY:
            console->log("LOADLIBRARY\n");
            break;
        case INJMETHOD::MANUALMAP:
            console->log("MANUALMAP\n");
            break;
    }

    system("pause");
    return 0;
}
