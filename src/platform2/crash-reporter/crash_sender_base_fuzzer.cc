// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <brillo/key_value_store.h>

#include "crash-reporter/crash_sender_base.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const std::string input = std::string(data, data + size);
  brillo::KeyValueStore output;

  util::ParseMetadata(input, &output);
  return 0;
}
