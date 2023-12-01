// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_DENY_USB_DEVICE_CLASS_RULE_H_
#define PERMISSION_BROKER_DENY_USB_DEVICE_CLASS_RULE_H_

#include <string>

#include "permission_broker/usb_subsystem_udev_rule.h"

namespace permission_broker {

class DenyUsbDeviceClassRule : public UsbSubsystemUdevRule {
 public:
  explicit DenyUsbDeviceClassRule(const uint8_t device_class);
  DenyUsbDeviceClassRule(const DenyUsbDeviceClassRule&) = delete;
  DenyUsbDeviceClassRule& operator=(const DenyUsbDeviceClassRule&) = delete;

  ~DenyUsbDeviceClassRule() override = default;

  Result ProcessUsbDevice(struct udev_device* device) override;

 private:
  const std::string device_class_;
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_DENY_USB_DEVICE_CLASS_RULE_H_
