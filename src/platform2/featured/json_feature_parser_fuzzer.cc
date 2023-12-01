// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <string>

#include <base/check_op.h>

#include "featured/service.h"

namespace featured {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const std::string data_string(data, data + size);

  JsonFeatureParser parser;
  parser.ParseFileContents(data_string);

  return 0;
}

}  // namespace featured
