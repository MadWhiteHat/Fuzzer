#include <iostream>
#include <fstream>
#include <string>

#include "utility.h"

void
MyProgram::Log(const std::string& __logFilename, const std::string& __msg) {
	std::fstream __log(__logFilename, std::fstream::app);
	if (!__log.is_open()) { return; }
	__log << __msg << std::endl;
	__log.close();
}
