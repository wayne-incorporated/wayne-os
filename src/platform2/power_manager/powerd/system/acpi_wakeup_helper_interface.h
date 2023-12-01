// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_ACPI_WAKEUP_HELPER_INTERFACE_H_
#define POWER_MANAGER_POWERD_SYSTEM_ACPI_WAKEUP_HELPER_INTERFACE_H_

#include <string>

namespace power_manager::system {

// Helper class to manipulate ACPI wakeup settings.
class AcpiWakeupHelperInterface {
 public:
  AcpiWakeupHelperInterface() = default;
  AcpiWakeupHelperInterface(const AcpiWakeupHelperInterface&) = delete;
  AcpiWakeupHelperInterface& operator=(const AcpiWakeupHelperInterface&) =
      delete;

  virtual ~AcpiWakeupHelperInterface() = default;

  // Checks whether /proc/acpi/wakeup is available on this system.
  virtual bool IsSupported() = 0;

  // Determines whether ACPI wakeup is enabled for a given device. Returns true
  // on success.
  virtual bool GetWakeupEnabled(const std::string& device_name,
                                bool* enabled_out) = 0;

  // Enables or disables ACPI wakeup for a given device. Returns true on
  // success.
  virtual bool SetWakeupEnabled(const std::string& device_name,
                                bool enabled) = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_ACPI_WAKEUP_HELPER_INTERFACE_H_
