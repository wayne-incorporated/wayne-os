// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_ALLOW_TTY_DEVICE_RULE_H_
#define PERMISSION_BROKER_ALLOW_TTY_DEVICE_RULE_H_

#include "permission_broker/tty_subsystem_udev_rule.h"

namespace permission_broker {

// AllowTtyDeviceRule encapsulates the policy that TTY devices are allowed to be
// accessed. Any path passed to it that is owned by a device on the TTY
// subsystem is |ALLOW|'ed. All other paths are ignored.
class AllowTtyDeviceRule : public TtySubsystemUdevRule {
 public:
  AllowTtyDeviceRule();
  AllowTtyDeviceRule(const AllowTtyDeviceRule&) = delete;
  AllowTtyDeviceRule& operator=(const AllowTtyDeviceRule&) = delete;

  ~AllowTtyDeviceRule() override = default;

  Result ProcessTtyDevice(udev_device* device) override;
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_ALLOW_TTY_DEVICE_RULE_H_
