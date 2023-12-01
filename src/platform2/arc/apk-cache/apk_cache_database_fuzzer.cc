// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/apk-cache/apk_cache_database.h"

#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string string_to_escape(reinterpret_cast<const char*>(data), size);
  apk_cache::EscapeSQLString(string_to_escape);
  return 0;
}
