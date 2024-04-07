.386
.model flat
.stack 4096

.code
public @shellcode@0
@shellcode@0 proc
assume fs:nothing

start:
  ; Stack preparation
  push ebp
  mov ebp, esp
  ; Offset 0x00-0x20 : message string
  ; Offset 0x20-0x30 : SYSTEMTIME struct
  ; Offset 0x30-0x3c : user dll string "user32.dll"
  ; Offset 0x3c-0x48 : date format "dd.MM.yyyy "
  ; Offset 0x48-0x4c : GetLocalTimePtr
  ; Offset 0x4c-0x50 : GetDateFormatAPtr
  ; Offset 0x50-0x54 : GetTimeFormatAPtr
  ; Offset 0x54-0x58 : MessageBoxAPtr
  sub esp, 5ch
  push ebx
  push esi
  push edi

  ; "resu"
  mov dword ptr [ebp - 3ch], 72657375h
  ; "d.23"
  mov dword ptr [ebp - 38h], 642e3233h
  ; "\0\0ll"
  mov dword ptr [ebp - 34h], 00006c6ch

  ; "M.dd"
  mov dword ptr [ebp - 48h], 4d2e6464h
  ; "yy.M"
  mov dword ptr [ebp - 44h], 79792e4dh
  ; "\0 yy"
  mov dword ptr [ebp - 40h], 00207979h

  ; Find kernel address
  mov eax, fs:[30h]
  mov eax, dword ptr [eax + 0ch]
  mov eax, dword ptr [eax + 14h]
  mov eax, dword ptr [eax]
  mov eax, dword ptr [eax]
  mov esi, dword ptr [eax + 10h]

  ; Prepare call find_function for GetLocalTime
  mov edx, 57c97c97h
  mov ecx, esi

  call find_function
  mov dword ptr [ebp - 4ch], eax

  ; Prepare call find_function for GetDateFormatA
  mov edx, 85674582h
  mov ecx, esi

  call find_function
  mov dword ptr [ebp - 50h], eax

  ; Prepare call find_function for GetTimeFormatA
  mov edx, 7e678586h
  mov ecx, esi

  call find_function
  mov dword ptr [ebp - 54h], eax

  ; Prepare call find_function for ExitProcess
  mov edx, 125fcc46h
  mov ecx, esi

  call find_function
  mov edi, eax

  ; Prepare call find_function for LoadLibraryA
  mov edx, 8a4b4256h
  mov ecx, esi

  call find_function
  
  ; Prepare call LoadLibrary("user32.dll")
  lea ecx, [ebp - 3ch]
  push ecx
  call eax

  ; Obtain ptr to MessageBoxA if user32.dll handle is valid 
  test eax, eax
  jne find_message_box

  ; Otherwise ExitProcess(-1)
  push 0ffffffffh
  call edi

find_message_box:
  ; Prepare call find_function for MessageBoxA
  mov edx, 5aca9670h
  mov ecx, eax

  call find_function
  mov dword ptr [ebp - 58h], eax

  ; Prepare call GetLocalTime
  lea eax, [ebp - 30h]
  push eax

  call dword ptr [ebp - 4ch]

  ; Prepare call GetDateFormatA
  push 20h
  lea eax, [ebp - 20h]
  push eax
  lea eax, [ebp - 48h]
  push eax
  lea eax, [ebp - 30h]
  push eax
  push 0h
  push 0800h
  
  call dword ptr [ebp - 50h]

  ; Prepare call GetTimeFormatA
  push 15h
  lea eax, [ebp - 15h]
  push eax
  push 0h
  lea eax, [ebp - 30h]
  push eax
  push 0h
  push 0800h
  
  call dword ptr [ebp - 54h]

  ; Prepare call MessageBox
  push 0h
  push 0h
  lea eax, [ebp - 20h]
  push eax
  push 0h
  
  call dword ptr [ebp - 58h]

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
  je find_function_ret_success

  ; else continue iterate over function names
  mov ecx, dword ptr [ebp - 08h]
  inc esi

  ; if there are still function names continute iterate
  cmp esi, ebx
  jb func_loop

find_function_ret_fail:
  xor eax, eax
  jmp find_function_ret

find_function_ret_success:
  mov eax, dword ptr [ebp - 0ch]
  mov ecx, dword ptr [ebp - 10h]
  movzx eax, word ptr [eax + esi * 2]
  mov eax, dword ptr [ecx + eax * 4]
  add eax, edi

find_function_ret:
  pop edi
  pop esi
  pop ebx
  mov esp, ebp
  pop ebp
  ret

  dd 012345678h

@shellcode@0 endp

end
