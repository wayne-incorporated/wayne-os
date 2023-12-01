// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_TTY_SUBSYSTEM_UDEV_RULE_H_
#define PERMISSION_BROKER_TTY_SUBSYSTEM_UDEV_RULE_H_

#include <string>

#include "permission_broker/rule.h"

namespace permission_broker {

// TtySubsystemUdevRule is a Rule that calls ProcessTtyDevice on every
// device that belongs to the TTY subsystem. All other non-TTY devices are
// ignored by this rule.
class TtySubsystemUdevRule : public Rule {
 public:
  static std::string GetDevNodeGroupName(udev_device* device);

  explicit TtySubsystemUdevRule(const std::string& name);
  TtySubsystemUdevRule(const TtySubsystemUdevRule&) = delete;
  TtySubsystemUdevRule& operator=(const TtySubsystemUdevRule&) = delete;

  ~TtySubsystemUdevRule() override = default;

  // Called with every device belonging to the TTY subsystem. The return value
  // from ProcessTtyDevice is returned directly as the result of processing this
  // rule.
  virtual Result ProcessTtyDevice(udev_device* device) = 0;

  Result ProcessDevice(udev_device* device) override;
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_TTY_SUBSYSTEM_UDEV_RULE_H_
