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
  std::string __backupDir(".\\backup\\");
  std::string __dllName("func.dll");
  bool __res;

  __res = std::filesystem::exists(_exeName);
  if (!__res) { std::filesystem::copy(__backupDir + __exeName, __exeName); }

  __res = std::filesystem::exists(_confName);
  if (!__res) { std::filesystem::copy(__backupDir + _confName, _confName); }

  __res = std::filesystem::exists(__dllName);
  if (!__res) { std::filesystem::copy(__backupDir + __dllName, __dllName); }

  __res = LoadFile();
  if (!__res) { throw std::runtime_error("loading config file failed"); }
}

MyProgram::Fuzzer::~Fuzzer() = default;

void
MyProgram::Fuzzer::
SetDividingSigns(const std::vector<uint8_t>& __divs) { _divs = __divs; }

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
    __msg << std::hex << "Fuzzer add to end file" << __count << " bytes 0x"
      << std::setw(2) << uint32_t(__code);
  }	else {
    _data.insert(_data.begin() + __offset, __count, __code);
    __msg << "Fuzzer add to offset: 0x" << std::setw(16) << std::hex << __offset
      << std::dec << __count << " bytes 0x" << std::setw(2) << std::hex
      << uint32_t(__code);
  }

  _SaveFile();
  _Log(__msg.str(), true);
  MyProgram::Debugger __debugger(_exeName);
  __debugger.Run();
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
      __msg << " 0x" << std::setw(2) << uint32_t(__tmp);
      _data.push_back(__tmp);
    }
  }	else {
    __msg << "Fuzzer insert random bytes to offset: 0x"
      << std::hex << std::setw(16) << __offset << ":" << std::dec;
    for (size_t i = 0; i < __count; ++i) {
      __tmp = _RandomByte();
      __msg << __count << " 0x" << std::setw(2) << std::hex
        << uint32_t(__tmp) << " ";
      _data.insert(_data.begin() + __offset + i, 1, __tmp);
    }
  }
  _Log(__msg.str(), true);
  _SaveFile();
  MyProgram::Debugger __debugger(_exeName);
  __debugger.Run();
}

void
MyProgram::Fuzzer::
DeleteByte(size_t __offset, size_t __count) {
  size_t __len = _data.size();
  std::stringstream __msg;
  if (__len == 0) {
    _Log("Config file not loaded", true);
    return;
  }
  if (__offset >= __len) {
    _Log("Offset greater than file size", true);
    return;
  }
  _data.erase(_data.begin() + __offset, _data.begin() + __offset + __count);
  _SaveFile();
  MyProgram::Debugger __debugger(_exeName);
  __debugger.Run();
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

void
MyProgram::Fuzzer::
ExpandFields(size_t __offset, uint32_t __code, size_t __count) {
  bool __findDiv = false;
  size_t __len = _data.size();
  size_t __divLen = _divs.size();
  size_t __pos = 0;
  size_t i = 0;
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
  } else {
    do {
      std::stringstream __msg;
      __msg.fill('0');
      if (__code <= 0xff) {
        _data.insert(_data.begin() + __pos, 1, uint8_t(__code));
        __msg << "Expand field at offset: 0x" << std::setw(16) << std::hex << __pos
          << " - byte 0x" << std::setw(2) << uint8_t(__code);
        __pos += 2;
        ++i;
        _Log(__msg.str(), true);
        if (i == __count) { break; }
      } else if ((__code > 0xff) && (__code <= 0xffff)) {
        _data.insert(_data.begin() + __pos, 1, uint8_t(__code));
        _data.insert(_data.begin() + __pos + 1, 1, uint8_t(__code >> 8));
        __msg << "Expand field at offset: 0x" << std::setw(16) << std::hex << __pos
          << " - word 0x" << std::setw(4) << uint16_t(__code);
        __pos += 3;
        ++i;
        _Log(__msg.str(), true);
        if (i == __count) { break; }
      } else if (__code > 0xffff) {
        _data.insert(_data.begin() + __pos, 1, uint8_t(__code));
        _data.insert(_data.begin() + __pos + 1, 1, uint8_t(__code >> 8));
        _data.insert(_data.begin() + __pos + 2, 1, uint8_t(__code >> 16));
        _data.insert(_data.begin() + __pos + 3, 1, uint8_t(__code >> 24));
        __msg << "Expand field at offset: 0x" << std::setw(16) << std::hex << __pos
          << " - dword 0x" << std::setw(8) << uint32_t(__code);
        __pos += 5;
        ++i;
        _Log(__msg.str(), true);
        if (i == __count) { break; }
      }
      __len = _data.size();
      __pos = _FindDividings(__pos);
    } while (__pos <= __len);
    _SaveFile();
    MyProgram::Debugger __debugger(_exeName);
    __debugger.Run();
  }
}

void
MyProgram::Fuzzer::
DryRun() {
  _SaveFile();
  MyProgram::Debugger __debugger(_exeName);
  __debugger.Run();
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

bool 
MyProgram::Fuzzer::
FindDividings() {
  bool __findDiv = false;
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
      __msg << "Dividing field found - " << _data[__pos] << "hex 0x"
        << std::setw(2) << std::hex << uint8_t(_data[__pos]) << " offset: 0x"
        << std::setw(16) << __pos;
      _Log(__msg.str(), true);
      __pos = _FindDividings(__pos + 1);
    } while (__pos <= __len);
  }
  return true;
}


void 
MyProgram::Fuzzer::
ChangeRandBytes(size_t __offset, size_t __count) {
  uint8_t __tmp;
  size_t __len = _data.size();
  if (__len == 0) {
    _Log("Config file not loaded", true);
    return;
  }
  if (__offset >= __len - 1) {
    _Log("Offset greater than file size", true);
    return;
  }
  for (size_t i = 0; i < __count; i++) {
    __tmp = _RandomByte();
    _ChangeByte(__offset + i, __tmp, true);
    if (__offset + i >= __len - 1) { break; }
  }

  _SaveFile();
  MyProgram::Debugger __debugger(_exeName);
  __debugger.Run();
  LoadFile();
}

void 
MyProgram::Fuzzer::
ChangeBytes(size_t __offset, uint32_t __bytes, size_t __count) {
  size_t __len = _data.size();
  DWORD __res = 0;
  size_t __counter = 0;
  if (__len == 0) {
    _Log("Config file not loaded", true);
    return;
  }
  if (__offset < __len) {
    MyProgram::Debugger __debugger(_exeName);
    if (__bytes <= 0xff) {
      uint8_t __tmp;
      for (size_t i = 0; i < __len - __offset; ++i) {
        __tmp = _data[__offset + i];
        _ChangeByte(__offset + i, uint8_t(__bytes), true);
        _SaveFile();
        __res = __debugger.Run();
        _ChangeByte(__offset + i, __tmp, false);
        if (__res > 0) { break; }
        ++__counter;
        if (__counter >= __count && __count != 0) { break; }
      }
    }
    if (__bytes > 0xff && __bytes <= 0xffff) {
      uint16_t __tmp;
      for (size_t i = 0; i < __len - __offset - 1; ++i) {
        __tmp = (_data[__offset + i + 1] << 8) + _data[__offset + i];
        _ChangeWord(__offset + i, uint16_t(__bytes), true);
        _SaveFile();
        __res = __debugger.Run();
        _ChangeWord(__offset + i, __tmp, false);
        if (__res > 0) { break; }
        ++__counter;
        if (__counter >= __count && __count != 0) { break; }
      }
    }
    if (__bytes > 0xffff) {
      uint32_t __tmp;
      for (size_t i = 0; i < __len - __offset - 3; i++) {
        __tmp = (_data[__offset + i + 3] << 24) + (_data[__offset + i + 2] << 16)
          + (_data[__offset + i + 1] << 8) + _data[__offset + i];
        _ChangeDWord(__offset + i, __bytes, true);
        _SaveFile();
        _ChangeDWord(__offset + i, __tmp, false);
        __res = __debugger.Run();
        if (__res > 0) { break; }
        ++__counter;
        if (__counter >= __count && __count != 0) { break; }
      }
    }
  }	else { _Log("Offset greater than file size", true); }
}

void 
MyProgram::Fuzzer::
_ChangeByte(size_t __offset, uint8_t __code, bool __verbose) {
  std::stringstream __msg;
  __msg.fill('0');
  __msg << "Offset: 0x" << std::hex << std::setw(16) << __offset
    << " fuzzer change BYTE from 0x" << std::setw(2) << uint32_t(_data[__offset])
    << " to 0x" << std::setw(2) << uint32_t(__code);
  _data[__offset] = __code;
  if (__verbose) { _Log(__msg.str(), true); }
}

void 
MyProgram::Fuzzer::
_ChangeWord(size_t __offset, WORD __code, bool __verbose) {
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
}

void 
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
}

bool
MyProgram::Fuzzer::
LoadFile() {
  std::ifstream __cfgFile(_confName, std::ios::binary);
  if (__cfgFile.is_open()) {

    __cfgFile.seekg(0, __cfgFile.end);
    auto __length = __cfgFile.tellg();
    __cfgFile.seekg(0, __cfgFile.beg);

    _data.clear();
    _data.reserve(size_t(__length));
    
    while (__cfgFile.good() && !__cfgFile.eof()) {
      _data.push_back(__cfgFile.get());
    }

    if (!__cfgFile.eof()) { return false; }

    __cfgFile.close();
  }
  else {
    _Log("Cannot open config file", true);
    return false;
  }
  return true;
}


bool
MyProgram::Fuzzer::
_SaveFile() {
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

uint8_t
MyProgram::Fuzzer::
_RandomByte(){
  static std::default_random_engine gen;
  std::uniform_int_distribution<> dist(0, 0xff);
  return dist(gen);
}

void
MyProgram::Fuzzer::
_Log(const std::string& __msg, bool __verbose) {
  std::string __log("fuzzer.log");
  if (__verbose) { std::cout << __msg << "\n"; }
  MyProgram::Log(__log, __msg);
}