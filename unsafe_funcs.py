from idaapi import *
ea = get_screen_ea()
seg = getseg(ea)
func = get_func(seg.startEA)
UnsafeFuncs = ["memcpy","wmemcpy","memmove","wmemmove","memset", "realloc", "calloc",
				"strcpy","wcscpy", "strncpy","wcsncat", "wcstombs", "strstr",
				"strcat","wcscat", "strncat","wcsncat", "wcslen", "strlen", "IsDBCSLeadByteEx",
				"sprintf","swprintf","vsprintf", "vfprintf", "strcoll", "atoi",
				"vswprintf","snprintf","vsnprintf", "strchr", "printf", "_setmode",
				"scanf","wscanf","vscanf","vwscanf", "signal", "puts", "fwrite",
				"fscanf","fwscanf","vfscanf","vfwscanf", "mbstowcs", "getenv", "MultiByteToWideChar",
				"sscanf","swscanf","vsscanf","vswscanf", "gets", "malloc", "WideCharToMultiByte"]
while func is not None and func.startEA < seg.endEA:
    funcea = func.startEA
    if (GetFunctionName(funcea) in UnsafeFuncs):
        print "Function %s at 0x%x" %(GetFunctionName(funcea), funcea)
    func = get_next_func(funcea)