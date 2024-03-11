#include "dr_api.h"
#include "drmgr.h"
#include "droption.h"
#include <string.h>

#define OUTPUT_FILE_DIR "output"
#define OUTPUT_FILE_PATH OUTPUT_FILE_DIR "\\ins_count.txt"

static uint64 ins_count = 0;

static void
inscount(uint num_instrs) { ins_count += num_instrs; }

static void
exit_event() {
  dr_enable_console_printing();

  dr_printf("Hello world!");

  bool dir_exists = dr_directory_exists(OUTPUT_FILE_DIR);
  if (!dir_exists) { dr_create_dir(OUTPUT_FILE_DIR); }

  file_t out = dr_open_file(OUTPUT_FILE_PATH, DR_FILE_WRITE_OVERWRITE);
  if (out != INVALID_FILE) {
    dr_write_file(out, &ins_count, sizeof(ins_count));
    dr_close_file(out);
  }

  drmgr_exit();
}

static dr_emit_flags_t
bb_analysis_event(
  void* drcontext,
  void* tag,
  instrlist_t* bb,
  bool for_trace,
  bool translating,
  void** user_data
) {
  instr_t* instr = NULL;
  uint num_instrs = 0;
  bool is_emulation = false;

  /* Count instructions. If an emulation client is running with this client,
   * we want to count all the original native instructions and the emulated
   * instruction but NOT the introduced native instructions used for emulation.
   */
  for (instr = instrlist_first(bb); instr != NULL; instr = instr_get_next(instr)) {
    if (drmgr_is_emulation_start(instr)) {
      /* Each emulated instruction is replaced by a series of native
       * instructions delimited by labels indicating when the emulation
       * sequence begins and ends. It is the responsibility of the
       * emulation client to place the start/stop labels correctly.
       */
      ++num_instrs;
      is_emulation = true;
      /* Data about the emulated instruction can be extracted from the
       * start label using the accessor function:
       * drmgr_get_emulated_instr_data()
       */
      continue;
    }
    if (drmgr_is_emulation_end(instr)) {
      is_emulation = false;
      continue;
    }
    if (is_emulation) { continue; }
    ++num_instrs;
  }
  *user_data = (void*)(ptr_uint_t)num_instrs;
  return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
instruction_event(
  void* drcontext,
  void* tag,
  instrlist_t* bb,
  instr_t* instr,
  bool for_trace,
  bool translating,
  void* user_data
) {
  uint num_instrs;
  /* By default drmgr enables auto-predication, which predicates all instructions with
   * the predicate of the current instruction on ARM.
   * We disable it here because we want to unconditionally execute the following
   * instrumentation.
   */
  drmgr_disable_auto_predication(drcontext, bb);

  if (!drmgr_is_first_instr(drcontext, instr)) { return DR_EMIT_DEFAULT; }

  /* Only insert calls for in-app BBs */
  if (user_data == NULL) { return DR_EMIT_DEFAULT; }
    
  /* Insert clean call */
  num_instrs = (uint)(ptr_uint_t)user_data;
  dr_insert_clean_call(
    drcontext, bb, instrlist_first_app(bb), (void*)inscount, false, 1,
    OPND_CREATE_INT32(num_instrs)
  );

  return DR_EMIT_DEFAULT;
}

static bool
exception_event(void* drcontext, dr_exception_t* excpt) {

  if (excpt->record->ExceptionCode != EXCEPTION_BREAKPOINT) {
    drmgr_exit();
    dr_exit_process(EXIT_FAILURE);
  }

  return true;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char* argv[]) {
  dr_set_client_name("My instructions counter", NULL);
    
  drmgr_init();

  /* register events */
  dr_register_exit_event(exit_event);
  drmgr_register_bb_instrumentation_event(
    bb_analysis_event, instruction_event, NULL
  );
  drmgr_register_exception_event(exception_event);
}