// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_DENY_GROUP_TTY_DEVICE_RULE_H_
#define PERMISSION_BROKER_DENY_GROUP_TTY_DEVICE_RULE_H_

#include <string>

#include "permission_broker/tty_subsystem_udev_rule.h"

namespace permission_broker {

class DenyGroupTtyDeviceRule : public TtySubsystemUdevRule {
 public:
  explicit DenyGroupTtyDeviceRule(const std::string& group_name);
  DenyGroupTtyDeviceRule(const DenyGroupTtyDeviceRule&) = delete;
  DenyGroupTtyDeviceRule& operator=(const DenyGroupTtyDeviceRule&) = delete;

  ~DenyGroupTtyDeviceRule() override = default;

  Result ProcessTtyDevice(udev_device* device) override;

 private:
  const std::string group_name_;
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_DENY_GROUP_TTY_DEVICE_RULE_H_
