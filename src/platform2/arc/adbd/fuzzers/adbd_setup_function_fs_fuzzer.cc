/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "arc/adbd/adbd.h"

#include <cstddef>
#include <cstdint>

#include <base/logging.h>

struct Environment {
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  std::string udc_driver_name(data, data + size);
  adbd::SetupFunctionFS(udc_driver_name);

  return 0;
}
