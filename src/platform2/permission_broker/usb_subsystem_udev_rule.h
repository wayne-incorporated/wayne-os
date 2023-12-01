// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_USB_SUBSYSTEM_UDEV_RULE_H_
#define PERMISSION_BROKER_USB_SUBSYSTEM_UDEV_RULE_H_

#include <string>

#include "permission_broker/rule.h"

namespace permission_broker {

// UsbSubsystemUdevRule is a Rule that calls ProcessUsbDevice on every
// device that belongs to the USB subsystem. All other non-USB devices are
// ignored by this rule.
class UsbSubsystemUdevRule : public Rule {
 public:
  explicit UsbSubsystemUdevRule(const std::string& name);
  UsbSubsystemUdevRule(const UsbSubsystemUdevRule&) = delete;
  UsbSubsystemUdevRule& operator=(const UsbSubsystemUdevRule&) = delete;

  ~UsbSubsystemUdevRule() override = default;

  // Called with every device belonging to the USB subsystem. The return value
  // from ProcessUsbDevice is returned directly as the result of processing this
  // rule.
  virtual Result ProcessUsbDevice(struct udev_device* device) = 0;

  Result ProcessDevice(struct udev_device* device) override;
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_USB_SUBSYSTEM_UDEV_RULE_H_
