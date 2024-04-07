#include <stdio.h>
#include <windows.h>

extern int __fastcall shellcode();
void __declspec(naked) END_SHELLCODE(void) {}

int shellcode_len() {
  int* ptr = shellcode;
  int length = 0;
  while (*ptr != 0x12345678) {
    ++length;
    ++((char*)ptr);
  }

  return length;
}

int __cdecl main() {
  // 57c97c97h ror13_hash("GetLocalTime")
  // 85674582h ror13_hash("GetDateFormatA")
  // 7e678586h ror13_hash("GetTimeFormatA")
  // 125fcc46h ror13_hash("ExitProcess")
  // 8a4b4256h ror13_hash("LoadLibraryA")
  // 5aca9670h ror13_hash("MessageBoxA")

  FILE *output_file = fopen("shellcode.bin", "w");
  fwrite(shellcode, 1, shellcode_len(), output_file);
  fclose(output_file);

  return 0;
}