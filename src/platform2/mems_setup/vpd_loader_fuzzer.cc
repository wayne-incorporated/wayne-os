// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>

#include "mems_setup/delegate_impl.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::map<std::string, std::string> cache;
  std::string fuzz_string(reinterpret_cast<const char*>(data), size);
  mems_setup::LoadVpdFromString(fuzz_string, &cache);
  return 0;
}
