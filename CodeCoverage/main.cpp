/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

 //
 // This tool counts the number of times a routine is executed and
 // the number of instructions executed in a routine
 //

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <unordered_set>
#include "pin.H"

// Holds instruction count for a single procedure
typedef struct RtnCount
{
  std::string _name;
  ADDRINT _address;
} RTN_COUNT;

// Linked list of instruction counts for each routine
static std::vector<RTN_COUNT*> trace;
bool enable_trace = false;
static const std::unordered_set <std::string> func_to_track = {
  "puts",
  "printf",
  "memset",
  "memcpy",
  "sprintf",
  "exit",
  "fopen",
  "fseek",
  "fread",
  "fflush",
  "fclose",
  "strstr",
  "strlen"
};

void log_result(INT32 exit_code) {
  std::ofstream out("trace.out");
  if (out.is_open()) {
    for (const auto& rc : trace) { out << rc->_address << '\n'; }
    out << exit_code;

    out.close();
  }
}

// This function is called before every instruction is executed
static VOID add_rtnc(RTN_COUNT* rtnc) {
  if (rtnc->_name == "main") { enable_trace = true; }
  if (enable_trace) { trace.push_back(rtnc); }
}

static std::string get_module_name(RTN* rtn) {
  std::string module_name = IMG_Name(SEC_Img(RTN_Sec(*rtn)));

  auto pos = module_name.rfind('\\');
  if (pos != std::string::npos && ++pos < module_name.length()) {
    module_name = module_name.substr(pos);
  }

  return module_name;
}

static bool is_track_func(
  const std::string& module_name, const std::string& func_name
) {
  if (module_name.ends_with(".exe")
    || module_name == "func.dll"
    || func_to_track.contains(func_name)
  ) {
    return true;
  } else { return false; }
}


// Pin calls this function every time a new rtn is executed
static VOID Routine(RTN rtn, VOID* v) {
  // Allocate a counter for this routine

  std::string module_name = get_module_name(&rtn);
  std::string func_name = RTN_Name(rtn);

  if (!is_track_func(module_name, func_name)) { return; }

  // The RTN goes away when the image is unloaded, so save it now
  // because we need it in the fini
  RTN_COUNT* rc = new RTN_COUNT;

  rc->_name = func_name;
  rc->_address = RTN_Address(rtn);

  RTN_Open(rtn);

  // Insert a call at the entry point of a routine to increment the call count
  RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)add_rtnc, IARG_PTR, rc, IARG_END);

  RTN_Close(rtn);
}

static EXCEPT_HANDLING_RESULT ExceptionHandler(
  THREADID tid,
  EXCEPTION_INFO* pExcptionInfo,
  PHYSICAL_CONTEXT* pPhysCont,
  VOID* v
) {

  std::cout << "Caught" << std::endl;
  PIN_ExitApplication(EXIT_SUCCESS);
}

// This function is called when the application exits
static VOID Fini(INT32 code, VOID* v) {
  log_result(code);

  for (auto& rc : trace) { delete(rc); }
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

static INT32 Usage()
{
  std::cerr << "This Pintool tracks subroutine calls after main" << std::endl;
  std::cerr << std::endl << KNOB_BASE::StringKnobSummary() << std::endl;
  return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
  // Initialize symbol table code, needed for rtn instrumentation
  PIN_InitSymbols();

  // Initialize pin
  if (PIN_Init(argc, argv)) return Usage();

  trace.reserve(10000);
  // Register Routine to be called to instrument rtn
  RTN_AddInstrumentFunction(Routine, 0);

  // Register exception handler
  PIN_AddInternalExceptionHandler(ExceptionHandler, 0);

  // Register Fini to be called when the application exits
  PIN_AddFiniFunction(Fini, 0);

  // Start the program, never returns
  PIN_StartProgram();

  return 0;
}