// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_CROS_EC_HELPER_INTERFACE_H_
#define POWER_MANAGER_POWERD_SYSTEM_CROS_EC_HELPER_INTERFACE_H_

namespace power_manager::system {

// Helper class to manipulate EC settings.
class CrosEcHelperInterface {
 public:
  CrosEcHelperInterface() = default;
  CrosEcHelperInterface(const CrosEcHelperInterface&) = delete;
  CrosEcHelperInterface& operator=(const CrosEcHelperInterface&) = delete;

  virtual ~CrosEcHelperInterface() = default;

  // Checks whether EC supports setting wake angle.
  virtual bool IsWakeAngleSupported() = 0;

  // Controls whether the EC will allow keyboard wakeups in tablet mode.
  // Returns true on success.
  virtual bool AllowWakeupAsTablet(bool enabled) = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_CROS_EC_HELPER_INTERFACE_H_
