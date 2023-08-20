#include <iostream>
#include <filesystem>


#include "fuzzer.h"
#include "debugger.h"
#include "utility.h"

#define LEVEL '\t'

inline void Usage() {
	std::cout << "Program for fuzzing config file\n"
		<< "Valid parameters for execution:\n"
		<< LEVEL << "0 - Exit program\n"
		<< LEVEL << "1 - Autofuzzing change bytes in original config\n"
		<< LEVEL << "2 - Autofuzzing append bytes in original config\n"
		<< LEVEL << "3 - Change bytes in file\n"
		<< LEVEL << "4 - Add bytes to file\n"
		<< LEVEL << "5 - Delete bytes from file\n"
		<< LEVEL << "6 - Find dividing fields\n"
		<< LEVEL << "7 - Expand fields\n"
		<< LEVEL << "8 - Reload original config file\n"
		<< LEVEL << "9 - Run with current confing\n"
		<< LEVEL << "10 - Print current config\n"
		<< LEVEL << "11 - Save current config\n";
}

int main(const int argc, const char** argv) {
	std::vector<uint8_t> __divs = {0x28 , 0x93, 0x2C, 0x3A , 0x3D, 0x3B, 0x94, 0x29};
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
	__fuzzer.SetDividingSigns(__divs);

	while (true) {
		system("cls");
		Usage();

		std::cout << "Input command: ";
		std::cin >> __choice;

		switch (__choice) {
			case 0: { return 0; }
			case 1:
				__fuzzer.ChangeAutoFuzzer();
				break;
			case 2:
				__fuzzer.AppendAutoFuzzer();
				break;
			case 3: {
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
			case 4: {
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
			case 5: {
				size_t __offset;
				size_t __count;
				std::cout << "Input start offset: ";
				std::cin >> __offset;
				std::cout << "Input count of bytes to delete: ";
				std::cin >> __count;
				__fuzzer.DeleteByte(__offset, __count);
				break;
			}
			case 6:
				__fuzzer.FindDividings();
				break;
			case 7: {
				size_t __inner_choice;
				size_t __offset;
				uint32_t __bytes;
				size_t __count;
				std::cout << "Input start offset: ";
				std::cin >> __offset;
				std::cout << "Input count fielsd of expand: ";
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
			case 8:
				__fuzzer.Backup();
				__fuzzer.LoadConfig();
				break;
			case 9:
				__fuzzer.DryRun();
				break;
			case 10:
				__fuzzer.PrintConfig();
				break;
			case 11:
				__fuzzer.SaveConfig();
				break;
		}
		system("pause");
	}
	return 0;
}