// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fuzzer/FuzzedDataProvider.h>

#include <base/logging.h>

#include "dlcservice/boot/boot_device.h"

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_FATAL); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider fuzzed_data_provider(data, size);

  dlcservice::BootDevice boot_device;

  std::string device = fuzzed_data_provider.ConsumeRemainingBytesAsString();
  boot_device.IsRemovableDevice(device);
  boot_device.GetBootDevice();
  return 0;
}
