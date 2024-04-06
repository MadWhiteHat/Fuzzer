#include <stdio.h>
#include <Windows.h>
//#include <winternl.h>
//#include <wchar.h>
//#include <tlhelp32.h>

//FARPROC __stdcall getlocaltime(DWORD stadd);

DWORD __stdcall ror13_hash(const char* string) {
  DWORD hash = 0;
  while (*string) {
    DWORD val = (DWORD)*string++;
    //if (val>='a' && val<='z') val = val - ('a' - 'A');
    hash = (hash >> 13) | (hash << 19);  // ROR 13
    hash += val;
  }
  return hash;
}

FARPROC __stdcall find_function(HMODULE module, DWORD hash) {
  IMAGE_DOS_HEADER* dos_header;
  IMAGE_NT_HEADERS* nt_headers;
  IMAGE_EXPORT_DIRECTORY* export_dir;
  DWORD* names, * funcs;
  WORD* nameords;
  int i;

  dos_header = (IMAGE_DOS_HEADER*)module;
  nt_headers = (IMAGE_NT_HEADERS*)((char*)module + dos_header->e_lfanew);
  export_dir = (IMAGE_EXPORT_DIRECTORY*)((char*)module + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  names = (DWORD*)((char*)module + export_dir->AddressOfNames);
  funcs = (DWORD*)((char*)module + export_dir->AddressOfFunctions);
  nameords = (WORD*)((char*)module + export_dir->AddressOfNameOrdinals);

  for (i = 0; i < export_dir->NumberOfNames; i++)
  {
    char* string = (char*)module + names[i];
    if (hash == ror13_hash(string))
    {
      WORD nameord = nameords[i];
      DWORD funcrva = funcs[nameord];
      return (FARPROC)((char*)module + funcrva);
    }
  }

  return NULL;
}

int main() {
  SYSTEMTIME st;
  char str[32];
  char usr[] = "user32.dll";
  char form[] = "dd.MM.yyyy ";
  HMODULE lib;
  FARPROC addr;
  lib = GetModuleHandle("KERNEL32.DLL");
  printf("KERNEL base is: 0x%08p\n",lib);
  DWORD prHash;
  prHash = ror13_hash("GetLocalTime");
  printf("Hash GetLocalTime: %08p\n", prHash);
  FARPROC getlocaltime =  find_function(lib, 0xB98C88CF);
  addr = GetProcAddress(lib,"GetLocalTime");
  printf("getlocaltime address: %08p\n", (DWORD)getlocaltime);
  printf("GetLocalTime address: %08p\n", addr);

  prHash = ror13_hash("GetDateFormatA");
  printf("Hash GetDateFormat: %08p\n", prHash);
  FARPROC getdateformat =  find_function(lib, 0xF72A53BA);
  addr = GetProcAddress(lib,"GetDateFormatA");
  printf("getdateformat address: %08p\n", getdateformat);
  printf("GetDateFormat address: %08p\n", addr);

  prHash = ror13_hash("GetTimeFormatA");
  printf("Hash GetTimeFormat: %08p\n", prHash);
  FARPROC gettimeformat =  find_function(lib, 0xF02A93BE);
  addr = GetProcAddress(lib,"GetTimeFormatA");
  printf("gettimeformat address: %08p\n", gettimeformat);
  printf("GetTimeFormat address: %08p\n", addr);

  prHash = ror13_hash("LoadLibraryA");
  printf("Hash LoadLibraryA: %08p\n", prHash);
  FARPROC loadlibrary =  find_function(lib, 0xEC0E4E8E);
  addr = GetProcAddress(lib,"LoadLibraryA");
  printf("loadlibraryA address: %08p\n", loadlibrary);
  printf("LoadLibraryA address: %08p\n", addr);

  lib = (HMODULE)loadlibrary("user32.dll");
  {
    lib = LoadLibrary("user32.dll");
    printf("USER32 base is: 0x%08p\n",lib);
  }
  printf("USER32 base is: 0x%08p\n",lib);

  prHash = ror13_hash("MessageBoxA");
  printf("Hash MessageBoxA: %08X\n", prHash);
  FARPROC messagebox =  find_function(lib, 0xBC4DA2A8);
  addr = GetProcAddress(lib,"MessageBoxA");
  printf("messagebox address: %08p\n", messagebox);
  printf("MessageBox address: %08p\n", addr);
  printf("sizeof ST: %08X\n", sizeof(st));
  getlocaltime(&st);
  getdateformat(2048,0,&st,&form,&str,32);
  gettimeformat(2048,0,&st,NULL,&str[11],18);
  messagebox(NULL, &str, "hack", 0x0000000L);
}
