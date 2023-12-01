// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/filesystem_label.h"

#include <string>

#include <base/logging.h>

// Disable logging.
struct Environment {
  Environment() { logging::SetMinLogLevel(logging::LOGGING_FATAL); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  std::string label(reinterpret_cast<const char*>(data), size);

  cros_disks::ValidateVolumeLabel(label, "vfat");
  cros_disks::ValidateVolumeLabel(label, "exfat");
  cros_disks::ValidateVolumeLabel(label, "ntfs");

  return 0;
}
