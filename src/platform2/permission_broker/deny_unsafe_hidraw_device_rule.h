// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_DENY_UNSAFE_HIDRAW_DEVICE_RULE_H_
#define PERMISSION_BROKER_DENY_UNSAFE_HIDRAW_DEVICE_RULE_H_

#include "permission_broker/hidraw_subsystem_udev_rule.h"

namespace permission_broker {

// DenyUnsafeHidrawDeviceRule encapsulates the policy that certain unsafe HID
// devices cannot be accessed through the hidraw subsystem. Namely this denies
// access to hidraw interfaces exposed by keyboards, mice, other pointing
// devices, and system control devices All other device types are ignored.
class DenyUnsafeHidrawDeviceRule : public HidrawSubsystemUdevRule {
 public:
  DenyUnsafeHidrawDeviceRule();
  DenyUnsafeHidrawDeviceRule(const DenyUnsafeHidrawDeviceRule&) = delete;
  DenyUnsafeHidrawDeviceRule& operator=(const DenyUnsafeHidrawDeviceRule&) =
      delete;

  ~DenyUnsafeHidrawDeviceRule() override = default;

  Result ProcessHidrawDevice(struct udev_device* device) override;

  static bool IsUnsafeUsage(const HidUsage& usage);
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_DENY_UNSAFE_HIDRAW_DEVICE_RULE_H_
