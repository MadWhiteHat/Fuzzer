#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include "drsyms.h"

#include "options.h"

#include <unordered_map>
#include <vector>

// Maps module name to load state false = unloaded
static std::unordered_map<module_data_t*, bool> modules_info;
using modules_info_entry_t = decltype(modules_info)::value_type;
// State of tracing
static bool trace = false;

static std::vector<uint64> addrs;

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

  dr_printf("Fuzzing method offset: 0x%x\nCalling convention: 0x%x\n", options.fuzz_offset, options.callconv);
}

static void
exit_event() {
  for (const auto& addr : addrs) {
    dr_printf("0x%08x\n", addr);
  }
  for (auto& module_info : modules_info) {
    dr_free_module_data(module_info.first);
  }
  dr_printf("Exit event %d", addrs.size());
  drwrap_exit();
  drmgr_exit();
}

static void pre_fuzz_handler(void* wrapcxt, void** user_data) {
  // Enable tracing in while main is called
  trace = true;
  dr_printf("In pre fuzz handler");
}

static void post_fuzz_handler(void* wrapcxt, void* user_data) {
  // Stop tracing after finishing main
  trace = false;
  dr_printf("In post fuzz handler");
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

  if (excpt->record->ExceptionCode != EXCEPTION_BREAKPOINT) {
    dr_printf("0x%x\n", excpt->record->ExceptionCode);
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