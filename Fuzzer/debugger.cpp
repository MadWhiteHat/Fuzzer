#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <windows.h>
#include <processthreadsapi.h>
#include <dbghelp.h>

#include "debugger.h"
#include "utility.h"

MyProgram::Debugger::
Debugger(const std::string& __exeName) : _exeName(__exeName), _waitTime(500) {}

DWORD
MyProgram::Debugger::Run() {
  BOOL __bRes = FALSE;
  DWORD __exitCode = 0;
  STARTUPINFOA __startInfo;
  PROCESS_INFORMATION __procInfo;
  std::stringstream __msg;
  __msg.fill('0');
  ZeroMemory(&__startInfo, sizeof(__startInfo));
  __startInfo.cb = sizeof(__startInfo);
  ZeroMemory(&__procInfo, sizeof(__procInfo));
  __bRes = CreateProcessA(
    _exeName.c_str(),
    NULL,
    NULL,
    NULL,
    FALSE,
    DEBUG_ONLY_THIS_PROCESS,
    NULL,
    NULL,
    &__startInfo,
    &__procInfo
  );
  if (!__bRes) {
    __msg << "Debugger cannot CreateProcess to debug. Error: 0x" << std::hex 
      << std::setw(8) << GetLastError();
    _Log(__msg.str(), true);
  }

  DEBUG_EVENT __debugEvent = { 0 };
  while (true) {
    if (!WaitForDebugEvent(&__debugEvent, _waitTime)) {
      GetExitCodeProcess(__procInfo.hProcess, &__exitCode);
      if (__exitCode != STILL_ACTIVE) {
        __msg << "Test no Exception. ExitCode: 0x" << std::hex << std::setw(8)
          << __exitCode;
        _Log(__msg.str(), true);
        return __exitCode;
      } else { continue; }
    }
    if (__debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
      __exitCode = _DebugEventInfo(__debugEvent, __procInfo);
      if (__exitCode != EXCEPTION_BREAKPOINT) { break; }
    }
    ContinueDebugEvent(
      __debugEvent.dwProcessId,
      __debugEvent.dwThreadId,
      DBG_CONTINUE
    );
  }
  TerminateProcess(__procInfo.hProcess, GetLastError());  
  return __exitCode;
}

DWORD
MyProgram::Debugger::
_DebugEventInfo(DEBUG_EVENT& __debugEvent, PROCESS_INFORMATION& __procInfo) {
  CONTEXT __context;
  std::stringstream __msg;
  std::string __exTextCode;
  uint8_t* __stackDump;
  __msg.fill('0');
  __context.ContextFlags = CONTEXT_ALL;
  if (GetThreadContext(__procInfo.hThread, &__context)) {
    DWORD __exCode = __debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
    switch (__exCode) {
      case EXCEPTION_ACCESS_VIOLATION:
        __exTextCode = "EXCEPTION_ACCESS_VIOLATION";
        break;
      case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        __exTextCode = "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
        break;
      case EXCEPTION_DATATYPE_MISALIGNMENT:
        __exTextCode = "EXCEPTION_DATATYPE_MISALIGNMENT";
        break;
      case EXCEPTION_FLT_DENORMAL_OPERAND:
        __exTextCode = "EXCEPTION_FLT_DENORMAL_OPERAND";
        break;
      case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        __exTextCode = "EXCEPTION_FLT_DIVIDE_BY_ZERO";
        break;
      case EXCEPTION_FLT_INEXACT_RESULT:
        __exTextCode = "EXCEPTION_FLT_INEXACT_RESULT";
        break;
      case EXCEPTION_FLT_INVALID_OPERATION:
        __exTextCode = "EXCEPTION_FLT_INVALID_OPERATION";
        break;
      case EXCEPTION_FLT_OVERFLOW:
        __exTextCode = "EXCEPTION_FLT_OVERFLOW";
        break;
      case EXCEPTION_FLT_STACK_CHECK:
        __exTextCode = "EXCEPTION_FLT_STACK_CHECK";
        break;
      case EXCEPTION_FLT_UNDERFLOW:
        __exTextCode = "EXCEPTION_FLT_UNDERFLOW";
        break;
      case EXCEPTION_ILLEGAL_INSTRUCTION:
        __exTextCode = "EXCEPTION_ILLEGAL_INSTRUCTION";
        break;
      case EXCEPTION_IN_PAGE_ERROR:
        __exTextCode = "EXCEPTION_IN_PAGE_ERROR";
        break;
      case EXCEPTION_INT_DIVIDE_BY_ZERO:
        __exTextCode = "EXCEPTION_INT_DIVIDE_BY_ZERO";
        break;
      case EXCEPTION_INT_OVERFLOW:
        __exTextCode = "EXCEPTION_INT_OVERFLOW";
        break;
      case EXCEPTION_INVALID_DISPOSITION:
        __exTextCode = "EXCEPTION_INVALID_DISPOSITION";
        break;
      case EXCEPTION_NONCONTINUABLE_EXCEPTION:
        __exTextCode = "EXCEPTION_NONCONTINUABLE_EXCEPTION";
        break;
      case EXCEPTION_PRIV_INSTRUCTION:
        __exTextCode = "EXCEPTION_PRIV_INSTRUCTION";
        break;
      case EXCEPTION_SINGLE_STEP:
        __exTextCode = "EXCEPTION_SINGLE_STEP";
        break;
      case EXCEPTION_STACK_OVERFLOW:
        __exTextCode = "EXCEPTION_STACK_OVERFLOW";
        break;
    }
    if (__exCode != EXCEPTION_BREAKPOINT) {
      if (__debugEvent.u.Exception.dwFirstChance == 1) {
        __msg << "First chance exception at 0x" << std::setw(8) << std::hex
          << __debugEvent.u.Exception.ExceptionRecord.ExceptionAddress
          << " " << __exTextCode << " code: 0x" << std::setw(8)
          << __debugEvent.u.Exception.ExceptionRecord.ExceptionCode << "\n"
          << "EAX = 0x" << std::setw(8) << __context.Eax << ' '
          << "EBX = 0x" << std::setw(8) << __context.Ebx << '\n'
          << "ECX = 0x" << std::setw(8) << __context.Ecx << ' '
          << "EDX = 0x" << std::setw(8) << __context.Edx << '\n'
          << "ESI = 0x" << std::setw(8) << __context.Esi << ' '
          << "EDI = 0x" << std::setw(8) << __context.Edi << '\n'
          << "EIP = 0x" << std::setw(8) << __context.Eip << ' '
          << "ESP = 0x" << std::setw(8) << __context.Esp << '\n'
          << "EBP = 0x" << std::setw(8) << __context.Ebp << ' '
          << "EFL = 0x" << std::setw(8) << __context.EFlags << '\n'
          << "CS = 0x" << std::setw(4) << __context.SegCs << ' '
          << "DS = 0x" << std::setw(4) << __context.SegDs << '\n'
          << "ES = 0x" << std::setw(4) << __context.SegEs << ' '
          << "FS = 0x" << std::setw(4) << __context.SegFs << '\n'
          << "GS = 0x" << std::setw(4) << __context.SegGs << '\n'
          << "ContextFlags = 0x" << std::setw(8) << __context.ContextFlags
          << "\n";
        DWORD __length = __context.Ebp - __context.Esp;
        if (__length > 0) {
          __stackDump = new(std::nothrow) uint8_t[__length];
          if (__stackDump != nullptr) {
            std::memset(__stackDump, 0x00, __length);
            void* __baseAddr = reinterpret_cast<void*>(__context.Esp);
            DWORD __totalRead = 0;
            ReadProcessMemory(__procInfo.hProcess, __baseAddr, __stackDump,
              __length, &__totalRead);
            __msg << "Stack frame:";
            if (__length > 0x40) { __length = 0x40; }
            for (DWORD i = 0; i < __length; ++i) {
              __msg << " 0x" << std::setw(2) << uint32_t(__stackDump[i]);
            }
            __msg << "\n";
          }
        }
        STACKFRAME64 __stackFrame;
        std::memset(&__stackFrame, 0x00, sizeof(__stackFrame));
        __stackFrame.AddrPC.Offset = __context.Eip;
        __stackFrame.AddrPC.Mode = AddrModeFlat;
        __stackFrame.AddrStack.Offset = __context.Esp;
        __stackFrame.AddrStack.Mode = AddrModeFlat;
        __stackFrame.AddrFrame.Offset = __context.Ebp;
        __stackFrame.AddrFrame.Mode = AddrModeFlat;
        int32_t __depth = 0;
        __msg << "Call stack:\n";
        while (StackWalk64(
            IMAGE_FILE_MACHINE_I386,
          __procInfo.hProcess,
          __procInfo.hThread,
          &__stackFrame,
          &__context,
          NULL, NULL, NULL, NULL
        )) {
          if (__stackFrame.AddrFrame.Offset == 0) { break; }
          __msg << "#" << std::dec << ++__depth << ' ' <<  std::hex
            << std::setw(16) << __stackFrame.AddrPC.Offset << '\n';
        }
        _Log(__msg.str() , true);
      }
    }
    return __exCode;
  } else {
    __msg << "Debugger cannot get thread context. Error: " << GetLastError();
    _Log(__msg.str(), true);
    return 0;
  }
}

void
MyProgram::Debugger::
_Log(const std::string& __msg, bool __verbose) {
  static std::string __log(LOG_FILE_PATH);
  if (__verbose) { std::cout << __msg << "\n"; }
  MyProgram::Log(__log, __msg);
}
