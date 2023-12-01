// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/acpi_wakeup_helper.h"

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include "fuzzer/FuzzedDataProvider.h"

#include "power_manager/powerd/system/fake_acpi_wakeup_file.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider data_provider(data, size);

  // Create a random device name, and random file contents, and then call
  // GetWakeupEnabled() with the two.
  auto file = std::make_unique<power_manager::system::FakeAcpiWakeupFile>();
  auto device_name = data_provider.ConsumeRandomLengthString(20);
  auto file_contents = data_provider.ConsumeRemainingBytesAsString();
  file->set_contents(file_contents.c_str());
  power_manager::system::AcpiWakeupHelper helper;
  helper.set_file_for_testing(std::move(file));

  bool enabled;
  helper.GetWakeupEnabled(device_name, &enabled);

  return 0;
}
