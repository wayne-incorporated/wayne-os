// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/acpi_wakeup_helper_stub.h"

namespace power_manager::system {

AcpiWakeupHelperStub::AcpiWakeupHelperStub() = default;
AcpiWakeupHelperStub::~AcpiWakeupHelperStub() = default;

bool AcpiWakeupHelperStub::IsSupported() {
  return true;
}

bool AcpiWakeupHelperStub::GetWakeupEnabled(const std::string& device_name,
                                            bool* enabled_out) {
  std::map<std::string, bool>::iterator it = wakeup_enabled_.find(device_name);
  if (it == wakeup_enabled_.end())
    return false;
  *enabled_out = it->second;
  return true;
}

bool AcpiWakeupHelperStub::SetWakeupEnabled(const std::string& device_name,
                                            bool enabled) {
  wakeup_enabled_[device_name] = enabled;
  return true;
}

}  // namespace power_manager::system
