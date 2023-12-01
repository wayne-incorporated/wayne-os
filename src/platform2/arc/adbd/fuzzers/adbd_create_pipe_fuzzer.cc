// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/adbd/adbd.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include <base/logging.h>

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  std::string file_path(data, data + size);
  adbd::CreatePipe(base::FilePath(file_path));

  return 0;
}
