#include "injection/injection.h"

int main(int argc, char** argv) {
    console->clear();
    console->log(LogLevel::orange, "[sigma mapper]\n\n");

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
    }

    RAWFILE dll(filePath);
    if (!dll) {
        console->report(LogLevel::error, "RAWFILE failed\n");
        return 1;
    }

    TARGETPROC process(procName, dll);
    if (!process) {
        console->report(LogLevel::error, "TARGETPROC failed\n");
        return 1;
    }

    system("pause");
    return 0;
}
