// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>

#include "u2fd/client/u2f_apdu.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const char* begin = reinterpret_cast<const char*>(data);
  uint16_t status;
  const auto result = u2f::U2fCommandApdu::ParseFromString(
      std::string(begin, begin + size), &status);

  // Get some extra coverage if parsing succeeded.
  if (result.has_value()) {
    result.value().ToString();
  }
  return 0;
}
