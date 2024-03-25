#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include "drsyms.h"

#include "options.h"

#include <unordered_map>
#include <vector>
#include <sstream>
#include <iomanip>

#include <windows.h>
#include <dbghelp.h>


// Maps module name to load state false = unloaded
static std::unordered_map<module_data_t*, bool> modules_info;
using modules_info_entry_t = decltype(modules_info)::value_type;
// State of tracing
static bool trace = false;

// Traced addresses
static std::vector<uint64> addrs;
static DWORD exit_code = ERROR_SUCCESS;

static HANDLE pipe = INVALID_HANDLE_VALUE;

static void print_options() {
  for (const auto& target_module : options.target_modules) {
    dr_printf("Target module: %s\n", target_module.c_str());
  }

  if (!options.fuzz_module.empty()) {
    dr_printf("Fuzzing module: %s\n", options.fuzz_module);
  }

  if (!options.fuzz_method.empty()) {
    dr_printf("Fuzzing method: %s\n", options.fuzz_method);
  }

  dr_printf(
    "Fuzzing method offset: 0x%x\nCalling convention: 0x%x\nLog dir:%s\n",
    options.fuzz_offset, options.callconv, options.log_dir
  );
}

static void write_to_file() {
  file_t fd = dr_open_file("trace.txt", DR_FILE_WRITE_OVERWRITE);
  if (fd == INVALID_FILE) { return; }

  dr_fprintf(fd, "0x%08x\n", addrs.size());
  for (const auto& addr : addrs) {
    dr_fprintf(fd, "0x%08x\n", addr);
  }

  dr_fprintf(fd, "0x%08x", exit_code);
}

static void
exit_event() {
  write_to_file();

  for (auto& module_info : modules_info) {
    dr_free_module_data(module_info.first);
  }

  drwrap_exit();
  drmgr_exit();
}

// Enable tracing in while main is called
static void pre_fuzz_handler(void* wrapcxt, void** user_data) {
  trace = true;
}

// Stop tracing after finishing main
static void post_fuzz_handler(void* wrapcxt, void* user_data) {
  trace = false;
}

static void module_load_event(
  void* drcontext, const module_data_t* info, bool loaded
) {
  std::string module_name;
  app_pc to_wrap = 0;
  module_data_t* new_module = NULL;

  {
    const char* name = info->names.exe_name;
    if (name == NULL) {
      // In case exe_name is not defined, we will fall back on the preferred name.
      name = dr_module_preferred_name(info);
    }
    module_name.assign(name);
  }


  if (!options.fuzz_module.empty()) {
    if (module_name == options.fuzz_module) {
      if (options.fuzz_offset) { to_wrap = info->start + options.fuzz_offset; }
      else {
        to_wrap = reinterpret_cast<app_pc>(
          dr_get_proc_address(info->handle, options.fuzz_method.c_str())
        );
        if (!to_wrap) {
          drsym_init(0);
          drsym_lookup_symbol(
            info->full_path,
            options.fuzz_method.c_str(),
            reinterpret_cast<size_t*>(&to_wrap),
            0
          );
          drsym_exit();

          DR_ASSERT_MSG(to_wrap, "Cannot find specified method in fuzz_module");
          to_wrap += reinterpret_cast<size_t>(info->start);
        }
      }

      drwrap_wrap_ex(
        to_wrap, pre_fuzz_handler, post_fuzz_handler, NULL, options.callconv
      );
    }
  }

  new_module = dr_copy_module_data(info);

  modules_info.emplace(new_module, true);
}

static void module_unlaod_event(void* drcontext, const module_data_t* info) {
  for (auto& module_info : modules_info) {
    if (module_info.first->start == info->start) {
      module_info.second = false;
      std::string module_name;
      {
        const char* name = info->names.exe_name;
        if (name == NULL) {
          // In case exe_name is not defined, we will fall back on the preferred name.
          name = dr_module_preferred_name(info);
        }

        module_name.assign(name);
      }
    }
  }
}

static bool pc_in_module(const modules_info_entry_t& entry, app_pc pc) {
  if (entry.second && entry.first != NULL) {
    const module_data_t* mod = entry.first;
    if (pc >= mod->start && pc < mod->end) { return true; }
  }

  return false;
}

static dr_emit_flags_t
instrument_bb_event(
  void* drcontext,
  void* tag,
  instrlist_t* bb,
  instr_t* instr,
  bool for_trace,
  bool translating,
  void* user_data
) {
  app_pc start_pc;
  std::string module_name;
  bool should_instrument;

  /* By default drmgr enables auto-predication, which predicates all instructions with
   * the predicate of the current instruction on ARM.
   * We disable it here because we want to unconditionally execute the following
   * instrumentation.
   */
  drmgr_disable_auto_predication(drcontext, bb);

  if (!drmgr_is_first_instr(drcontext, instr))
    return DR_EMIT_DEFAULT;

  start_pc = dr_fragment_app_pc(tag);

  auto begin = modules_info.begin();
  auto end = modules_info.end();

  for (; begin != end; ++begin) {
    if (pc_in_module(*begin, start_pc)) { break; }
  }

  // Not found
  if (begin == end || begin->first == NULL) { return DR_EMIT_DEFAULT; }

  const module_data_t* module = begin->first;
  module_name.assign(dr_module_preferred_name(module));

  should_instrument = false;
  for (const auto& target_module : options.target_modules) {
    if (target_module == module_name) {
      should_instrument = true;
      break;
    }
  }

  if (!should_instrument) {
    return dr_emit_flags_t(DR_EMIT_DEFAULT | DR_EMIT_PERSISTABLE);
  }

  if (trace) {
    addrs.push_back(uint64(start_pc - begin->first->start));
  }

  return DR_EMIT_DEFAULT;
}

static bool
exception_event(void* drcontext, dr_exception_t* excpt) {
  BOOL __bRes = FALSE;
  HANDLE __hProcess;
  HANDLE __hThread;
  CONTEXT __context;
  DWORD __length;
  uint8_t* __stackDump;
  std::stringstream __msg;
  
  __msg.fill('0');

  if (excpt->record->ExceptionCode != EXCEPTION_BREAKPOINT) {
    exit_code = excpt->record->ExceptionCode;
    __hProcess = GetCurrentProcess();
    __hThread = GetCurrentThread();

    __context.ContextFlags = CONTEXT_ALL;
    __bRes = GetThreadContext(__hThread, &__context);
    if (__bRes) {
      __msg << "Exception at 0x" << std::setw(8) << std::hex
        << excpt->record->ExceptionAddress << " code: 0x" << std::setw(8)
        << exit_code << "\n"
        << "EAX = 0x" << std::setw(8) << __context.Eax << ' '
        << "EBX = 0x" << std::setw(8) << __context.Ebx << '\n'
        << "ECX = 0x" << std::setw(8) << __context.Ecx << ' '
        << "EDX = 0x" << std::setw(8) << __context.Edx << '\n'
        << "ESI = 0x" << std::setw(8) << __context.Esi << ' '
        << "EDI = 0x" << std::setw(8) << __context.Edi << '\n'
        << "EIP = 0x" << std::setw(8) << __context.Eip << ' '
        << "ESP = 0x" << std::setw(8) << __context.Esp << '\n'
        << "EBP = 0x" << std::setw(8) << __context.Ebp << ' '
        << "EFL = 0x" << std::setw(8) << __context.EFlags << '\n'
        << "CS = 0x" << std::setw(4) << __context.SegCs << ' '
        << "DS = 0x" << std::setw(4) << __context.SegDs << '\n'
        << "ES = 0x" << std::setw(4) << __context.SegEs << ' '
        << "FS = 0x" << std::setw(4) << __context.SegFs << '\n'
        << "GS = 0x" << std::setw(4) << __context.SegGs << '\n'
        << "ContextFlags = 0x" << std::setw(8) << __context.ContextFlags
        << "\n";

      __length = __context.Ebp - __context.Esp;
      if (__length > 0) {
        __stackDump = new(std::nothrow) uint8_t[__length];
        if (__stackDump != nullptr) {
          std::memset(__stackDump, 0x00, __length);
          void* __baseAddr = reinterpret_cast<void*>(__context.Esp);
          DWORD __totalRead = 0;
          ReadProcessMemory(
            __hProcess, __baseAddr, __stackDump, __length, &__totalRead
          );
          __msg << "Stack frame:";
          if (__length > 0x40) { __length = 0x40; }
          for (DWORD i = 0; i < __length; ++i) {
            __msg << " 0x" << std::setw(2) << uint32_t(__stackDump[i]);
          }
          __msg << "\n";
        }
      }
      STACKFRAME64 __stackFrame;
      std::memset(&__stackFrame, 0x00, sizeof(__stackFrame));
      __stackFrame.AddrPC.Offset = __context.Eip;
      __stackFrame.AddrPC.Mode = AddrModeFlat;
      __stackFrame.AddrStack.Offset = __context.Esp;
      __stackFrame.AddrStack.Mode = AddrModeFlat;
      __stackFrame.AddrFrame.Offset = __context.Ebp;
      __stackFrame.AddrFrame.Mode = AddrModeFlat;
      int32_t __depth = 0;
      __msg << "Call stack:\n";
      while (StackWalk64(
        IMAGE_FILE_MACHINE_I386,
        __hProcess,
        __hThread,
        &__stackFrame,
        &__context,
        NULL, NULL, NULL, NULL
      )) {
        if (__stackFrame.AddrFrame.Offset == 0) { break; }
        __msg << "#" << std::dec << ++__depth << ' ' << std::hex
          << std::setw(16) << __stackFrame.AddrPC.Offset << '\n';
      }
      dr_printf("%s\n", __msg.str().data());
    }

    dr_exit_process(EXIT_FAILURE);
  }

  return true;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char** argv) {
  dr_set_client_name("Debugger client with function tracing", NULL);

  drmgr_init();
  drwrap_init();
  dr_enable_console_printing();

  parse_options(argc, argv);
  print_options();

  addrs.reserve(1000);

  /* register events */
  dr_register_exit_event(exit_event);
  drmgr_register_exception_event(exception_event);
  drmgr_register_module_load_event(module_load_event);
  drmgr_register_module_unload_event(module_unlaod_event);
  drmgr_register_bb_instrumentation_event(NULL, instrument_bb_event, NULL);
}