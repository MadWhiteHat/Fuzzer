#ifndef _OPTIONS_H
#define _OPTIONS_H

#include "dr_api.h"
#include "drwrap.h"
#include <unordered_set>
#include <string>

#define MIN_TARGET_MODULES (1 << 2)
#define USAGE_CHECK(x, msg) DR_ASSERT_MSG(x, msg)

struct options_t {
  std::unordered_set<std::string> target_modules;
  std::string fuzz_module;
  std::string fuzz_method;
  std::string log_dir;
  unsigned long fuzz_offset;
  drwrap_callconv_t callconv;
};

extern options_t options;

void parse_options(int argc, const char** argv);

#endif // !_OPTIONS_H
