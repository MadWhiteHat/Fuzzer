import immlib
import struct
import sys

def main(args):
	dbg = immlib.Debugger()
	dbg.createLogWindow()
	
	modules = get_modules_list(dbg)
	
	if len(args) == 0:	
		print_modules_info(dbg, modules)
	else:
		for mod_name in args:
			opcodes =	find_jmp_esp(dbg, mod_name, modules)
			print_module_jmp_esp(dbg, mod_name, modules, opcodes)
	return ""

def get_modules_list(dbg):

	all_modules = dbg.getAllModules()
	ret_modules = {}

	for mod_name in all_modules.keys():
		mod_obj = dbg.getModule(mod_name)

		if mod_obj == None:
			continue

		mod_aslr = True
		mod_dep = True
		mod_rebase = False
		mod_cfg = False

		mz_base = mod_obj.getBaseAddress()
		mz_rebase = mod_obj.getFixupbase()
		mz_size = mod_obj.getSize()
		
		mz_top = mz_base + mz_size
		
		if mz_base > 0:
			pe_offset = struct.unpack('<L',dbg.readMemory(mz_base + 0x3c, 4))[0]
			pe_base = mz_base + pe_offset
			
			# IMAGE_DLL_CHARACTERISTICS FIELD
			# Sits at offset 0x5e in Optional Header
			dll_flags = struct.unpack('<H',dbg.readMemory(pe_base + 0x5e, 2))[0]
			
			#aslr
			if (dll_flags & 0x0040) == 0:
				mod_aslr = False
			#dep
			if (dll_flags & 0x0100) == 0:
				mod_dep = False
			#cfg
			if (dll_flags & 0x4000) == 0:
				mod_cfg = False
			else:
				mod_cfg = True
			#rebase
			if mz_rebase != mz_base:
				mod_rebase = True
		
		
			ret_modules[mod_name] = {}

			ret_modules[mod_name]['aslr'] = mod_aslr
			ret_modules[mod_name]['dep'] = mod_dep
			ret_modules[mod_name]['cfg'] = mod_cfg
			ret_modules[mod_name]['rebase'] = mod_rebase
			ret_modules[mod_name]['base_addr'] = mz_base
			ret_modules[mod_name]['size'] = mz_size

		else:
			continue

	return ret_modules

def find_jmp_esp(dbg, mod_name, modules):
	unable2search = False
	search = []

	if mod_name not in modules.keys():
		dbg.log("Could not fing module %s" % mod_name)
		return search


	if modules[mod_name]['rebase'] == True: 
		dbg.log("Module %s can be rebased" % mod_name)
		unable2search = True

	if modules[mod_name]['aslr'] == True:
		dbg.log("Module %s has ASLR" % mod_name)
		unable2search = True

	if unable2search:
		return search

	search = get_search_list()

	return search_in_module(dbg, search, mod_name)


def get_search_list():
	offsets = [ "", "0x04","0x08","0x0c","0x10","0x12","0x1C","0x20","0x24"]
	registers = ["eax","ebx","ecx","edx","esi","edi","ebp"]
	search = []
	
	search_register = "esp"
	
	search.append("jmp " + search_register )
	search.append("call " + search_register)
	
	for roffset in offsets:
		search.append("push "+ search_register + "\nret "+ roffset)
		
	for register in registers:
		search.append("push " + search_register + "\npop "+ register + "\njmp " + register)
		search.append("push " + search_register + "\npop "+ register + "\ncall "+ register)			
		search.append("mov " + register + "," + search_register + "\njmp " + register)
		search.append("mov " + register + "," + search_register + "\ncall "+ register)
		search.append("xchg " + register + "," + search_register + "\njmp " + register)
		search.append("xchg "+ register + "," + search_register + "\ncall " + register)				
		for roffset in offsets:
			search.append("push " + search_register + "\npop "+ register +"\npush " + register + "\nret " + roffset)			
			search.append("mov " + register + "," + search_register + "\npush " + register + "\nret " + roffset)
			search.append("xchg " + register + "," + search_register + "\npush " + register + "\nret " + roffset)

	return search

def search_in_module(dbg, sequences, mod_name):
	mod = dbg.getModule(mod_name)
	
	# get the base and end address of the module
	start = mod.getBaseAddress()
	end = start + mod.getSize()

	found_opcodes = {}

	if not sequences:
		return {}

	if start > end:
		start, end = end, start

	dbg.getMemoryPages()
	process_error_found = False	
	
	for a in dbg.MemoryPages.keys():
		# get end address of the page
		page_start = a
		page_size = dbg.MemoryPages[a].getSize()
		page_end = a + page_size
		
		if ( start > page_end or end < page_start ):
			# we are outside the search range, skip
			continue
			
		# if the criteria check for nulls or unicode, we can skip
		# modules that start with 00
		start_fb = to_hex(page_start)[0:2]
		end_fb = to_hex(page_end)[0:2]
		
		mem = dbg.MemoryPages[a].getMemory()
		if not mem:
			continue
		
		# loop on each sequence
		for seq in sequences:
			buf = None
			human_format = ""
			if type(seq) == str:
				human_format = seq.replace("\n"," # ")
				buf = dbg.assemble(seq)
			else:
				human_format = seq[0].replace("\n"," # ")
				buf = seq[1]

			recur_find = []		
			try:
				buf_len = len(buf)
				mem_list = mem.split( buf )
				total_length = buf_len * -1
			except:
				process_error_found = True
				break
			
			for i in mem_list:
				total_length = total_length + len(i) + buf_len
				seq_address = a + total_length
				recur_find.append( seq_address )

			#The last one is the remaining slice from the split
			#so remove it from the list
			del recur_find[ len(recur_find) - 1 ]

			page_find = []
			for i in recur_find:
				if ( i >= start and i <= end ):
					
					page_find.append(i)
					
			#add current pointers to the list and continue		
			if len(page_find) > 0:
				if human_format in found_opcodes:
					found_opcodes[human_format] += page_find
				else:
					found_opcodes[human_format] = page_find
		if process_error_found:
			break

	return found_opcodes

def print_modules_info(dbg, modules):
	result_str = ""

	for mod_name, mod_vals in modules.iteritems():
		result_str = result_str + "ModuleName: %s\n  ASLR: %s\n  DEP: %s\n  Rebase: %s\n" \
		% (mod_name, mod_vals['aslr'], mod_vals['dep'], mod_vals['rebase'])
	if result_str != "":
		log_str = result_str.split('\n')
		for line in log_str:
			dbg.log(line)

def print_module_jmp_esp(dbg, mod_name, modules, opcodes):
	ptrcnt = 0
	cnt = 0
	
	dbg.log("%s:" % mod_name)

	if opcodes:
		for optext, pointers in opcodes.iteritems():
			for ptr in pointers:
				ptrinfo = ""
				modinfo = ""
				ptrextra = ""
				rva = 0
				if (modules[mod_name]['rebase'] or modules[mod_name]['aslr']):
					rva = ptr - modules[mod_name]['base_addr']
					ptrextra = " (b+0x" + to_hex(rva) + ") "
				ptrinfo = optext + " : " + "0x" + to_hex(ptr) + ptrextra
				dbg.log("  %s" % ptrinfo, address = ptr)
				ptrcnt += 1
	else:
		dbg.log("  None")
	dbg.log("    Found a total of %d pointers" % ptrcnt, highlight = 1)
	
def to_hex(n):
		return "%08x" % n