#include "options.h"

#include "droption.h"

options_t options;

void parse_options(int argc, const char** argv) {
  std::string token;

  options.target_modules.clear();
  options.target_modules.reserve(MIN_TARGET_MODULES);
  options.fuzz_module.clear();
  options.fuzz_module.reserve(MAX_PATH);
  options.fuzz_method.clear();
  options.fuzz_method.reserve(MAX_PATH);
  options.log_dir = "coverage.log";
  options.fuzz_offset = 0;
  options.callconv = DRWRAP_CALLCONV_DEFAULT;

  for (int i = 1; i < argc; ++i) {
    token.assign(argv[i]);

    if (token == "-target_module") {
      USAGE_CHECK((i + 1) < argc, "missing target module name");
      options.target_modules.insert(argv[++i]);
    } else if (token == "-fuzz_module") {
      USAGE_CHECK((i + 1) < argc, "missing fuzzing module name");
      USAGE_CHECK(options.fuzz_module.empty(), "fuzzing module name already set");
      options.fuzz_module.assign(argv[++i]);
    } else if (token == "-fuzz_method") {
      USAGE_CHECK((i + 1) < argc, "missing fuzzing method name");
      USAGE_CHECK(options.fuzz_method.empty(), "fuzzing method name already set");
      options.fuzz_method.assign(argv[++i]);
    } else if (token == "-fuzz_offset") {
      USAGE_CHECK((i + 1) < argc, "missing fuzzing method offset");
      options.fuzz_offset = std::strtoul(argv[++i], NULL, 0);
    } else if (token == "-call_convention") {
      USAGE_CHECK((i + 1) < argc, "missing calling convention");
      token.assign(argv[++i]);
      if (token == "stdcall") {
        options.callconv = DRWRAP_CALLCONV_CDECL;
      } else if (token == "fastcall") {
        options.callconv = DRWRAP_CALLCONV_FASTCALL;
      } else if (token == "thiscall") {
        options.callconv = DRWRAP_CALLCONV_THISCALL;
      } else if (token == "ms64") {
        options.callconv = DRWRAP_CALLCONV_MICROSOFT_X64;
      }
    } else if (token == "-log_dir") {
      USAGE_CHECK((i + 1) < argc, "missing log file directrory");
      options.log_dir.assign(argv[++i]);
    } else {
      USAGE_CHECK(false, (std::string("Invalid option: ") + token).c_str());
    }
  }
}
