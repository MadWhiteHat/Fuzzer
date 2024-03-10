#include <iostream>
#include <fstream>

#include "pin.H"


PIN_MUTEX mutex;
std::ofstream out;
static INT32 instCount = 0;

// This function is called before every instruction is executed
static VOID AddInst() {

  PIN_MutexLock(&mutex);
  
  ++instCount;
  out << instCount << '\n';

  PIN_MutexUnlock(&mutex);
}

// Pin calls this function every time a new instruction is encountered
static VOID Instruction(INS ins, VOID* v)
{
  // Insert a call to docount before every instruction, no arguments are passed
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)AddInst, IARG_END);
}

// This function is called when the application exits
static VOID Fini(INT32 code, VOID* v) {
  PIN_MutexLock(&mutex);
  out.close();
  PIN_MutexUnlock(&mutex);

  PIN_MutexFini(&mutex);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

static INT32 Usage() {
  std::cerr << "This tool counts the number of dynamic instructions executed" << std::endl;
  return EXIT_FAILURE;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */


INT32 main(int argc, char** argv)
{
  std::cout << "[CodeCoverage] Start..." << std::endl;
  if (PIN_Init(argc, argv)) { return Usage(); }

  out.open("out.txt");
  if (!out.is_open()) { return EXIT_FAILURE; }

  if (!PIN_MutexInit(&mutex)) { return EXIT_FAILURE; }

  INS_AddInstrumentFunction(Instruction, 0);
  PIN_AddFiniFunction(Fini, 0);

  std::cout << "[CodeCoverage] Program trace Start" << std::endl;

  PIN_StartProgram();
  std::exit(instCount);
}
