// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <cstddef>
#include <cstdint>

#include "stdin_util.h"

extern "C" {
#include "prnt/hpps/hppsfilter.h"

int hpps_main(int argc, char** argv);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const char* argv[] = {"" /*uri*/,         "1" /*JobID*/,
                        "chronos" /*user*/, "Untitled" /*title*/,
                        "1" /*copies*/,     "" /*options*/};
  int error = fuzzer_set_stdin(data, size);
  if (error) {
    std::cerr << "set_stdin() failed: error code " << error << std::endl;
    abort();
  }

  error = hpps_main(sizeof(argv) / sizeof(argv[0]), const_cast<char**>(argv));
  if (error) {
    std::cerr << "hpps_main failed: error code " << error << std::endl;
    abort();
  }
  return 0;
}
