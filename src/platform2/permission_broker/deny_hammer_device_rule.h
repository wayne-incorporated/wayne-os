// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_DENY_HAMMER_DEVICE_RULE_H_
#define PERMISSION_BROKER_DENY_HAMMER_DEVICE_RULE_H_

#include "permission_broker/usb_subsystem_udev_rule.h"

namespace permission_broker {

// Hammer detachable bases (keyboard + touchpad) typically would not be accessed
// by systems outside CrOS e.g. guest OSes. To prevent asking to the user to
// attach hammer to guest OSes, this rule denies access to hammer until we can
// provide a better UI for managing device access.
class DenyHammerDeviceRule : public UsbSubsystemUdevRule {
 public:
  DenyHammerDeviceRule();
  DenyHammerDeviceRule(const DenyHammerDeviceRule&) = delete;
  DenyHammerDeviceRule& operator=(const DenyHammerDeviceRule&) = delete;

  ~DenyHammerDeviceRule() override = default;

  Result ProcessUsbDevice(struct udev_device* device) override;
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_DENY_HAMMER_DEVICE_RULE_H_
