// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/mount_info.h"

#include <string>

struct Environment {
  Environment() {}
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  std::string str(reinterpret_cast<const char*>(data), size);

  cros_disks::MountInfo m;
  m.DecodePath(str);

  return 0;
}
