// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/deny_usb_vendor_id_rule.h"

#include <libudev.h>

#include <string>

#include "base/strings/stringprintf.h"

namespace permission_broker {

DenyUsbVendorIdRule::DenyUsbVendorIdRule(const uint16_t vendor_id)
    : UsbSubsystemUdevRule("DenyUsbVendorIdRule"),
      vendor_id_(base::StringPrintf("%.4x", vendor_id)) {}

Rule::Result DenyUsbVendorIdRule::ProcessUsbDevice(struct udev_device* device) {
  const char* vendor_id = udev_device_get_sysattr_value(device, "idVendor");
  if (vendor_id && (vendor_id_ == vendor_id))
    return DENY;
  return IGNORE;
}

}  // namespace permission_broker
