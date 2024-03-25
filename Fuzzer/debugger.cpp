#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <windows.h>
#include <aclapi.h>
#include <processthreadsapi.h>

#include "debugger.h"
#include "utility.h"

MyProgram::Debugger::
Debugger(const std::string& __exeName, const std::string& __options)
  : _exeName(__exeName),
    _options(__options) {

  ZeroMemory(&_startInfo, sizeof(_startInfo));
  _startInfo.cb = sizeof(_startInfo);
  ZeroMemory(&_procInfo, sizeof(_procInfo));
}

BOOL
MyProgram::Debugger::
DryRun() {
  BOOL __bRes = FALSE;

  __bRes = _CreateTargetProcess();
  if (!__bRes) { return __bRes; }

  _CloseTargetProcess();

  return __bRes;
}

std::vector<uint64_t>
MyProgram::Debugger::
GetTrace() {
  std::vector<uint64_t> __res;
  size_t __size;
  uint64_t __val;
  std::string __tracePath(PROGRAM_DIR);
  __tracePath += "\\trace.txt";

  std::ifstream __traceFile(__tracePath);
  if (!__traceFile.is_open()) { return __res; }

  __traceFile >> std::hex >> __size;
  __res.reserve(__size + 1);

  while (!__traceFile.eof()) {
    __traceFile >> std::hex >> __val;
    __res.push_back(__val);
  }

  if (__res.size() != __size + 1) { __res.clear(); }

  return __res;
}

BOOL
MyProgram::Debugger::
_ChangeCurrentDirectory(
  LPCSTR __newDir, LPSTR __prevDir, size_t __prevDirSize
) {
  BOOL __bRes = FALSE;
  DWORD __dwRes = ERROR_SUCCESS;
  CHAR __currDir[MAX_PATH] = { 0x00 };
  std::stringstream __msg;

  __msg.fill('0');

  // Store current directory
  if (__prevDir != NULL) {
    __bRes = GetCurrentDirectoryA(MAX_PATH, __currDir);
    if (!__bRes) {
      __dwRes = GetLastError();
      __msg << "GetCurrentDirectory failed. Error: 0x" << std::hex
        << std::setw(8) << __dwRes;
      _Log(__msg.str(), true);
      return __bRes;
    }

    snprintf(__prevDir, __prevDirSize, "%s", __currDir);
  }

  __bRes = SetCurrentDirectoryA(__newDir);
  if (!__bRes) {
    __dwRes = GetLastError();
    __msg << "SetCurrentDirectory failed. Error: 0x" << std::hex
      << std::setw(8) << __dwRes;
    _Log(__msg.str(), true);
    return __bRes;
  }

  return TRUE;
}

BOOL
MyProgram::Debugger::
_CreateTargetProcess() {
  BOOL __bRes = FALSE;
  DWORD __dwRes = ERROR_SUCCESS;
  CHAR __programDir[MAX_PATH] = { 0x00 };
  CHAR __currDir[MAX_PATH] = { 0x00 };
  std::string __commandLine;
  std::stringstream __msg;
  CHAR* __cmd;
  size_t __cmdSize;

  __msg.fill('0');
  __dwRes, __programDir;

  __commandLine = _exeName;
  if (!_options.empty()) {
    __commandLine += ' ' + _options;
  }

  __cmdSize = __commandLine.length() + 1;
  __cmd = new(std::nothrow) char[__cmdSize];
  if (__cmd == NULL) {
    __msg << "Memory allocation failed. Error: 0x" << std::hex
      << std::setw(8) << 0;
    _Log(__msg.str(), true);
    return __bRes;
  }

  std::snprintf(__cmd, __cmdSize, "%s", __commandLine.c_str());

  __bRes = GetFullPathNameA(PROGRAM_DIR, MAX_PATH, __programDir, NULL);
  if (!__bRes) {
    __dwRes = GetLastError();
    __msg << "GetFullPathName failed. Error: 0x" << std::hex
      << std::setw(8) << __dwRes;
    _Log(__msg.str(), true);
    return __bRes;
  }

  __bRes = _ChangeCurrentDirectory(__programDir, __currDir, MAX_PATH);
  if (!__bRes) { return __bRes; }

  ZeroMemory(&_startInfo, sizeof(_startInfo));
  _startInfo.cb = sizeof(_startInfo);
  ZeroMemory(&_procInfo, sizeof(_procInfo));

  __bRes = CreateProcessA(
    NULL,
    __cmd,
    NULL,
    NULL,
    FALSE,
    0,
    NULL,
    NULL,
    &_startInfo,
    &_procInfo
  );
  if (!__bRes) {
    __dwRes = GetLastError();
    __msg << "CreateProcess failed. Error: 0x" << std::hex
      << std::setw(8) << __dwRes;
    _Log(__msg.str(), true);
  }

  _ChangeCurrentDirectory(__currDir, NULL, 0);

  return __bRes;
}

void
MyProgram::Debugger::
_CloseTargetProcess() {
  WaitForSingleObject(_procInfo.hProcess, INFINITE);
  CloseHandle(_procInfo.hThread);
  CloseHandle(_procInfo.hProcess);
}

void
MyProgram::Debugger::
_Log(const std::string& __msg, bool __verbose) {
  static std::string __log(LOG_FILE_PATH);
  if (__verbose) { std::cout << __msg << "\n"; }
  MyProgram::Log(__log, __msg);
}
