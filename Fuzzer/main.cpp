#include <iostream>

#include "fuzzer.h"
#include "debugger.h"
#include "utility.h"

#define LEVEL '\t'

inline void Usage() {
  std::cout << "Program for fuzzing config file\n"
    << "Valid parameters for execution:\n"
    << LEVEL << "0 - Exit program\n"
    << LEVEL << "1 - Autofuzzing change bytes in original config\n"
    << LEVEL << "2 - Change bytes in file\n"
    << LEVEL << "3 - Add bytes to file\n"
    << LEVEL << "4 - Delete bytes from file\n"
    << LEVEL << "5 - Expand fields\n"
    << LEVEL << "6 - Dry run with current confing\n"
    << LEVEL << "7 - Create exploit config\n"
    << LEVEL << "8 - Reload original config file\n"
    << LEVEL << "9 - Save current config\n"
    << LEVEL << "10 - Print fields positions\n"
    << LEVEL << "11 - Print current config\n"
    ;
}

int main(const int argc, const char** argv) {
  std::string __variant;
  std::string __exeName;
  std::string __configName;
  size_t __choice = 0;
  
  if (argc == 1) {
    std::cout << "Pass a variant number as an argument\n";
    return 0;
  }

  __variant.assign(argv[1]);

  try {
    int __num = std::stoi(__variant);
    if (__num < 1 || __num > 54) {
      throw std::invalid_argument("Invalid variant");
    }
  } catch (std::exception& __ex) {
    std::cout << __ex.what() << '\n';
    return 0;
  }

  __exeName = "vuln" + __variant + ".exe";
  __configName = "config_" + __variant;

  MyProgram::Fuzzer __fuzzer(__exeName, __configName);
    while (true) {
      system("cls");
      Usage();

      std::cout << "Input command: ";
      std::cin >> __choice;

      switch (__choice) {
        case 0: { return 0; }
        case 1:
          __fuzzer.AutoFuzzer(2);
          break;
        case 2: {
          size_t __inner_choice;
          size_t __offset;
          uint32_t __bytes;
          size_t __count;
          std::cout << "Input start offset: ";
          std::cin >> __offset;
          std::cout << "Input count (0 = to EOF): ";
          std::cin >> __count;
          std::cout << "Choose type:" << std::endl;
          std::cout << LEVEL << "1. Random bytes\n";
          std::cout << LEVEL << "2. Input bytes value\n";
          std::cin >> __inner_choice;
          switch (__inner_choice) {
            case 1:
              __fuzzer.ChangeRandBytes(__offset, __count);
              break;
            case 2:
              std::cout << "Input bytes to change (Max value: 0xFFFFFFFF): ";
              std::cin >> std::hex >> __bytes >> std::dec;
              __fuzzer.ChangeBytes(__offset, __bytes, __count);
              break;
          }
          break;
        }
        case 3: {
          size_t __inner_choice;
          size_t __offset;
          uint16_t __byte;
          size_t __count;
          std::cout << "Input start offset: ";
          std::cin >> __offset;
          std::cout << "Input count of bytes to insert: ";
          std::cin >> __count;
          std::cout << "Choose type:" << std::endl;
          std::cout << LEVEL << "1. Random byte\n";
          std::cout << LEVEL << "2. Input byte value\n";
          std::cin >> __inner_choice;
          switch (__inner_choice) {
            case 1:
              __fuzzer.InsertRandomByte(__offset, __count);
              break;
            case 2:
              std::cout << "Input bytes to change (Max value: 0xFF): ";
              std::cin >> std::hex >> __byte >> std::dec;
              __fuzzer.InsertByte(__offset, (uint8_t)__byte, __count);
              break;
          }
          break;
        }
        case 4: {
          size_t __offset;
          size_t __count;
          std::cout << "Input start offset: ";
          std::cin >> __offset;
          std::cout << "Input count of bytes to delete: ";
          std::cin >> __count;
          __fuzzer.DeleteByte(__offset, __count);
          break;
        }
        case 5: {
          size_t __inner_choice;
          size_t __offset;
          uint32_t __bytes;
          size_t __count;
          std::cout << "Input start offset: ";
          std::cin >> __offset;
          std::cout << "Input count fields of expand: ";
          std::cin >> __count;
          std::cout << "Choose type:" << std::endl;
          std::cout << LEVEL << "1. Random byte\n";
          std::cout << LEVEL << "2. Input byte value\n";
          std::cin >> __inner_choice;
          switch (__inner_choice) {
            case 1: {
              __fuzzer.ExpandFieldsRandom(__offset, __count);
              break;
            }
            case 2: {
              std::cout << "Input bytes to change (Max value: 0xFFFFFFFF): ";
              std::cin >> std::hex >> __bytes >> std::dec;
              __fuzzer.ExpandFields(__offset, (uint32_t)__bytes, __count);
              break;
            }
          }
          break;
        }
        case 6:
          __fuzzer.DryRun();
          break;
        case 7:
          __fuzzer.CreateExploit();
          break;
        case 8:
          __fuzzer.Backup();
          __fuzzer.LoadConfig();
          break;
        case 9:
          __fuzzer.SaveConfig();
          break;
        case 10:
          __fuzzer.PrintFields();
          break;
        case 11:
          __fuzzer.PrintConfig();
          break;
    }
    system("pause");
  }
  return 0;
}