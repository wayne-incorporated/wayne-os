// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/allow_group_tty_device_rule.h"

namespace permission_broker {

AllowGroupTtyDeviceRule::AllowGroupTtyDeviceRule(const std::string& group_name)
    : TtySubsystemUdevRule("AllowGroupTtyDeviceRule"),
      group_name_(group_name) {}

Rule::Result AllowGroupTtyDeviceRule::ProcessTtyDevice(udev_device* device) {
  const std::string& device_gr_name = GetDevNodeGroupName(device);
  return group_name_ == device_gr_name ? ALLOW : IGNORE;
}

}  // namespace permission_broker
