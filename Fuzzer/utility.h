#ifndef _UTILITY_H
#define _UTILITY_H

#include <iostream>
#include <fstream>
#include <string>

#define BACKUP_DIR ".\\backup"
#define PROGRAM_DIR ".\\program"
#define LOG_DIR ".\\log"
#define DLL_NAME "func.dll"
#define LOG_FILE_PATH LOG_DIR "\\program.log"

namespace MyProgram {

void Log(const std::string& __logFilename, const std::string& __msg);

} // namespace MyProgram

#endif // _UTILITY_H
