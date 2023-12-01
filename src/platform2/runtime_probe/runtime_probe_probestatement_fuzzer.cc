// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>

#include <string>

#include <base/json/json_reader.h>
#include <base/logging.h>

#include "runtime_probe/probe_function.h"
#include "runtime_probe/probe_statement.h"
#include "runtime_probe/runtime_probe_fuzzer_helper.h"

#define rand_str(a) fuzz_data->ConsumeRandomLengthString((a))
#define rand_int() std::to_string(fuzz_data->ConsumeIntegral<int>())

using std::string;

namespace runtime_probe {

struct Environment {
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

inline string GetSysfsDictionary(FuzzedDataProvider* fuzz_data) {
  return R"({
    "sysfs": {
      "dir_path": ")" +
         JsonSafe(rand_str(30)) + R"(",
      "keys": [")" +
         JsonSafe(rand_str(30)) + R"("]
    }
  })";
}

inline string GetShellDictionary(FuzzedDataProvider* fuzz_data) {
  return R"({
    "shell": {
      "command": ")" +
         JsonSafe(rand_str(30)) + R"(",
      "key": ")" +
         JsonSafe(rand_str(30)) + R"("
    }
  })";
}

inline string GetEcI2cDictionary(FuzzedDataProvider* fuzz_data) {
  return R"({
    "ec_i2c": {
      "size": )" +
         rand_int() + R"(,
      "i2c_bus": )" +
         rand_int() + R"(,
      "chip_addr": )" +
         rand_int() + R"(,
      "data_addr": )" +
         rand_int() + R"(
    }
  })";
}

inline string GetVPDCachedDictionary(FuzzedDataProvider* fuzz_data) {
  return R"({
    "vpd_cached": {
      "vpd_name": ")" +
         JsonSafe(rand_str(30)) + R"("
    }
  })";
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  FuzzedDataProvider fuzz_data(data, size);

  int op = fuzz_data.ConsumeIntegralInRange<int8_t>(0, 3);
  string eval_str;

  switch (op) {
    case 0:
      eval_str = R"({
        "eval":)" +
                 GetSysfsDictionary(&fuzz_data) + R"(
      })";
      break;
    case 1:
      eval_str = R"({
        "eval":)" +
                 GetShellDictionary(&fuzz_data) + R"(
      })";
      break;
    case 2:
      eval_str = GetEcI2cDictionary(&fuzz_data);
      break;
    case 3:
      eval_str = GetVPDCachedDictionary(&fuzz_data);
      break;
    default:
      return 0;
  }

  auto eval = base::JSONReader::Read(eval_str);
  if (!eval.has_value())
    return 0;
  if (op == 0 || op == 1) {  // Fuzz Eval
    auto probe_statement = ProbeStatement::FromValue("nop", *eval);

    if (probe_statement != nullptr)
      auto results = probe_statement->Eval();
  } else {  // Fuzz EvalInHelper
    auto probe_function = runtime_probe::ProbeFunction::FromValue(*eval);

    if (probe_function != nullptr) {
      string output;
      probe_function->EvalInHelper(&output);
    }
  }

  return 0;
}

}  // namespace runtime_probe
