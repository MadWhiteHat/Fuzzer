from idaapi import *
ea = get_screen_ea()
seg = getseg(ea)
func = get_func(seg.startEA)

InputFuncs = [
	"fread", "fwrite", "fgets", "gets", "fgetws", "scanf", "fscanf", "sscanf",
	"vscanf","vfscanf", "vsscanf", "wscanf", "fwscanf", "wscanf", "fwscanf",
	"swscanf", "vwscanf", "vfwscanf", "vswscanf"
]

UnsafeFuncs = [
	# Unsafe input functions
	"fread", "fwrite", "fgets", "gets", "fgetws", "scanf", "fscanf", "sscanf",
	"vscanf","vfscanf", "vsscanf", "wscanf", "fwscanf", "wscanf", "fwscanf",
	"swscanf", "vwscanf", "vfwscanf", "vswscanf",

	# Potentially unsafe output functions (buffer is less than proided size)
	"fwrite", "snprintf", "sprintf_s", "snprintf_s", "vsnprintf", "vsprintf_s",
	"vsnprintf_s", "swprintf", "swprintf_s", "snwprintf_s", "vswprintf",
	"vswprintf_s", "vsnwprintf_s",
	
	# Potentially unsafe functions with null-terminated multibyte string
	"strcpy", "strcpy_s", "strncpy", "strncpy_s", "strcat", "strcat_s",
	"strncat", "strcnat_s", "memcmp", "memset", "memset_s", "memcpy",
	"memcpy_s", "memmove", "memmove_s", "memccpy",

	# Potentially unsafe functions with multibyte null-terminated string

	"mbtowc", "wctomb","wctomb_s", "mbstowcs", "mbstowcs_s", "wcstombs",
	"wcstombs_s", "mbrtowc", "wcrtomb", "wcrtomb_s", "mbsrtowcs",
	"mbsrtowcs_s", "wcsrtombs", "wcsrtombs_s", "mbrtoc8", "c8rtomb",
	"mbrtoc16", "c16rtomb", "mbrtoc32", "c32rtomb",

	# Potentially unsafe functions with null--terminated wide string
	"wcscpy", "wcscpy_s", "wcsncpy", "wcsncpy_s", "wcscat", "wcscat_s",
	"wcsncat", "wcsncat_s", "wmemcpy", "wmemcpy_s", "wmemmove", "wmemmove_s",
	"wmemset"
]

while func is not None and func.startEA < seg.endEA:
    funcea = func.startEA
    if (GetFunctionName(funcea) in InputFuncs):
     	print "Input function %s at 0x%x" %(GetFunctionName(funcea), funcea)

    if (GetFunctionName(funcea) in UnsafeFuncs):
        print "Potentially unsafe function %s at 0x%x" %(GetFunctionName(funcea), funcea)
    func = get_next_func(funcea)