// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_DENY_USB_VENDOR_ID_RULE_H_
#define PERMISSION_BROKER_DENY_USB_VENDOR_ID_RULE_H_

#include <stdint.h>

#include <string>

#include "permission_broker/usb_subsystem_udev_rule.h"

namespace permission_broker {

class DenyUsbVendorIdRule : public UsbSubsystemUdevRule {
 public:
  explicit DenyUsbVendorIdRule(const uint16_t vendor_id);
  DenyUsbVendorIdRule(const DenyUsbVendorIdRule&) = delete;
  DenyUsbVendorIdRule& operator=(const DenyUsbVendorIdRule&) = delete;

  ~DenyUsbVendorIdRule() override = default;

  Result ProcessUsbDevice(struct udev_device* device) override;

 private:
  const std::string vendor_id_;
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_DENY_USB_VENDOR_ID_RULE_H_
