// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/allow_hidraw_device_rule.h"

#include <libudev.h>

namespace permission_broker {

AllowHidrawDeviceRule::AllowHidrawDeviceRule()
    : HidrawSubsystemUdevRule("AllowHidrawDeviceRule") {}

Rule::Result AllowHidrawDeviceRule::ProcessHidrawDevice(
    struct udev_device* device) {
  return ALLOW;
}

}  // namespace permission_broker
