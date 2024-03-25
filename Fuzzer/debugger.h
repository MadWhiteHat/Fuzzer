#ifndef _DEBUGGER_H
#define _DEBUGGER_H

#include <iostream>
#include <string>
#include "windows.h"

#define PIPE_NAME "\\\\.\\pipe\\code_coverage"
#define PIPE_BUFFER_SIZE 4096
#define PIPE_TIMEOUT 5000

namespace MyProgram {

class Debugger {
public:
  Debugger(const std::string& __exeName, const std::string& __options);

  BOOL DryRun();
  std::vector<uint64_t> GetTrace();

private:
  BOOL _ChangeCurrentDirectory(
    LPCSTR __newDir, LPSTR __prevDir, size_t __prevDirSize
  );
  BOOL _CreateTargetProcess();
  void _CloseTargetProcess();

  static void _Log(const std::string& __msg, bool __verbose = false);

  std::string _exeName;
  std::string _options;
  STARTUPINFOA _startInfo;
  PROCESS_INFORMATION _procInfo;
};

} // namespace MyProgram

#endif // _DEBUGGER_H
