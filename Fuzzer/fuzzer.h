#ifndef _FUZZER_H
#define _FUZZER_H

#include <iostream>
#include <string>
#include <vector>
#include <windows.h>

#include "debugger.h"
#include "utility.h"

#define COVERAGE_DLL_PATH "../Release/CodeCoverage.dll"
#define CRASH_CONFIGS_DIR ".\\crash"

namespace MyProgram {

class Fuzzer {
public:
  enum class ExpandType {RANDOM, BYTE, WORD, DWORD};

  Fuzzer(
    const std::string& __exeName,
    const std::string& __confName
  );
  ~Fuzzer();

  // opt 1
  void
  AutoFuzzer(uint32_t __limitShift);

  // opt 2
  void
  ChangeBytes(size_t __offset, uint32_t __bytes, size_t __count);
  void
  ChangeRandBytes(size_t __offset, size_t __count);

  // opt 3
  void
  InsertByte(size_t __offset, uint8_t __code, size_t __count);
  void
  InsertRandomByte(size_t __offset, size_t __count);

  // opt 4
  void
  DeleteByte(size_t __offset, size_t __count);

  // opt 5
  void
  ExpandFields(size_t __offset, uint32_t __code, size_t __count);
  void
  ExpandFieldsRandom(size_t __offset, size_t __count);

  // opt 6
  BOOL
  DryRun();

  // opt 7
  uint32_t
  TraceRun();

  // opt 8
  void
  CreateExploit();

  // opt 9
  void
  Backup();
  bool
  LoadConfig();

  // opt 10
  bool
  SaveConfig();

  // opt 11
  void
  PrintFields();

  // opt 12
  void
  PrintConfig();

private:
  uint8_t
  _ChangeByte(size_t __offset, uint8_t __code, bool __verbose = false);
  uint16_t
  _ChangeWord(size_t __offset, uint16_t __code, bool __verbose = false);
  uint32_t
  _ChangeDWord(size_t __offset, uint32_t __code, bool __verbose = false);

  void
  _FindFields();

  std::string _FindDrrun();
  std::vector<uint64_t>
  _TraceRun();

  bool _SaveCrashConfig(size_t __offset, uint8_t __val, uint32_t __exitCode);
  bool _SaveCrashConfig(size_t __offset, uint16_t __val, uint32_t __exitCode);
  bool _SaveCrashConfig(size_t __offset, uint32_t __val, uint32_t __exitCode);
  bool _SaveCrashConfig(size_t __offset, std::string __val, uint32_t __exitCode);
  bool _SaveConfig(std::string __fileName);
 

  static void
  _Log(const std::string& __msg, bool __verbose = false);

  static uint8_t
  _RandomByte();

  std::vector<uint8_t> _data;
  std::vector<size_t> _fields;
  std::vector<uint64_t> _referenceTrace;
  std::string _exeName;
  std::string _confName;
  bool _dataChanged;

  // '(', '\"', ',' , ':', '=', ';', '^', ')'
  static std::vector<uint8_t> _divs;
};

} // namespace MyProgram

#endif // _FUZZER_H