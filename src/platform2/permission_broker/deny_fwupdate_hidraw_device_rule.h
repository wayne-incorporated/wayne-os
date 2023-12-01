// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_DENY_FWUPDATE_HIDRAW_DEVICE_RULE_H_
#define PERMISSION_BROKER_DENY_FWUPDATE_HIDRAW_DEVICE_RULE_H_

#include "permission_broker/hidraw_subsystem_udev_rule.h"

#include <unordered_map>
#include <vector>

namespace permission_broker {

struct ProductIdRange {
  int min;
  int max;
};

using RangeListMap = std::unordered_map<int, std::vector<ProductIdRange>>;

// DenyFwUpdateHidrawDeviceRule encapsulates the policy that a hidraw device
// that is used to update the device's firmware should not be accessible by
// Chrome. These devices are disallowed explicitly using vendor and
// product IDs.
class DenyFwUpdateHidrawDeviceRule : public HidrawSubsystemUdevRule {
 public:
  DenyFwUpdateHidrawDeviceRule();
  DenyFwUpdateHidrawDeviceRule(const DenyFwUpdateHidrawDeviceRule&) = delete;
  DenyFwUpdateHidrawDeviceRule& operator=(const DenyFwUpdateHidrawDeviceRule&) =
      delete;

  ~DenyFwUpdateHidrawDeviceRule() override = default;

  Result ProcessHidrawDevice(struct udev_device* device) override;

  bool IsFwUpdateDevice(const char* path, const RangeListMap& blockedDevices);
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_DENY_FWUPDATE_HIDRAW_DEVICE_RULE_H_
