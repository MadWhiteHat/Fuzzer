#ifndef _UTILITY_H
#define _UTILITY_H

#include <iostream>
#include <fstream>
#include <string>

#define LOG_FILE_PATH ".\\logs\\program.log"

namespace MyProgram {

void Log(const std::string& __logFilename, const std::string& __msg);

} // namespace MyProgram

#endif // _UTILITY_H
