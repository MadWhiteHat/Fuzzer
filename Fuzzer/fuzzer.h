#ifndef _FUZZER_H
#define _FUZZER_H

#include <iostream>
#include <string>
#include <vector>
#include <windows.h>

#define BACKUP_DIR ".\\backup"
#define PROGRAM_DIR ".\\program"
#define DLL "func.dll"

#include "debugger.h"

namespace MyProgram {

class Fuzzer {
public:
	enum class ExpandType {RANDOM, BYTE, WORD, DWORD};
	Fuzzer(
		const std::string& __exeName,
		const std::string& __confName
	);
	~Fuzzer();

	bool
  FindDividings();

	void
  ChangeBytes(size_t __offset, uint32_t __bytes, size_t __count);
	void
  ChangeRandBytes(size_t __offset, size_t __count);

	void
  InsertByte(size_t __offset, uint8_t __code, size_t __count);
	void
  InsertRandomByte(size_t __offset, size_t __count);

	void
  DeleteByte(size_t __offset, size_t __count);

	void
  ExpandFields(size_t __offset, uint32_t __code, size_t __count);
	void
  ExpandFieldsRandom(size_t __offset, size_t __count);

	void
  Backup();

	void
  PrintConfig();

	bool
  LoadConfig();

	bool
  SaveConfig();

	DWORD
  DryRun();

	void
	ChangeAutoFuzzer();

	void
  AppendAutoFuzzer();

	void
  CreateExploit();

private:
	uint8_t
  _ChangeByte(size_t __offset, uint8_t __code, bool __verbose = false);

	uint16_t
  _ChangeWord(size_t __offset, uint16_t __code, bool __verbose = false);

	uint32_t
  _ChangeDWord(size_t __offset, uint32_t __code, bool __verbose = false);

	size_t
  _FindDividings(size_t __offset);

	static void
  _Log(const std::string& __msg, bool __verbose = false);

	static uint8_t
  _RandomByte();

	std::vector<uint8_t> _data;
	std::string _exeName;
	std::string _confName;

  // '(', '\"', ',' , ':', '=', ';', '^', ')'
	static constexpr std::vector<uint8_t> _divs{
		0x28, 0x93, 0x2C, 0x3A, 0x3D, 0x3B, 0x94, 0x29
	};
};

} // namespace MyProgram

#endif // _FUZZER_H