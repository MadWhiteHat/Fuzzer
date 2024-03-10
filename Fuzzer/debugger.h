#ifndef _DEBUGGER_H
#define _DEBUGGER_H

#include <iostream>
#include "windows.h"
#include <string>

namespace MyProgram {

class Debugger {
public:
	Debugger(const std::string& __exeName);

	DWORD Run();

private:

	DWORD _DebugEventInfo(
		DEBUG_EVENT& __debugEvent,
		PROCESS_INFORMATION& __procInfo
	);
	static void _Log(const std::string& __msg, bool __verbose = false);

	std::string _exeName;
	DWORD _waitTime;
};

} // namespace MyProgram

#endif // _DEBUGGER_H
