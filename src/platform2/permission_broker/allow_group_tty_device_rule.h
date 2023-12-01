// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_ALLOW_GROUP_TTY_DEVICE_RULE_H_
#define PERMISSION_BROKER_ALLOW_GROUP_TTY_DEVICE_RULE_H_

#include <string>

#include "permission_broker/tty_subsystem_udev_rule.h"

namespace permission_broker {

class AllowGroupTtyDeviceRule : public TtySubsystemUdevRule {
 public:
  explicit AllowGroupTtyDeviceRule(const std::string& group_name);
  AllowGroupTtyDeviceRule(const AllowGroupTtyDeviceRule&) = delete;
  AllowGroupTtyDeviceRule& operator=(const AllowGroupTtyDeviceRule&) = delete;

  ~AllowGroupTtyDeviceRule() override = default;

  Result ProcessTtyDevice(udev_device* device) override;

 private:
  const std::string group_name_;
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_ALLOW_GROUP_TTY_DEVICE_RULE_H_
