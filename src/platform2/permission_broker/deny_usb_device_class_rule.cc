// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/deny_usb_device_class_rule.h"

#include <libudev.h>

#include "base/strings/stringprintf.h"

namespace permission_broker {

DenyUsbDeviceClassRule::DenyUsbDeviceClassRule(const uint8_t device_class)
    : UsbSubsystemUdevRule("DenyUsbDeviceClassRule"),
      device_class_(base::StringPrintf("%.2x", device_class)) {}

Rule::Result DenyUsbDeviceClassRule::ProcessUsbDevice(
    struct udev_device* device) {
  const char* device_class =
      udev_device_get_sysattr_value(device, "bDeviceClass");
  if (device_class && (device_class_ == device_class))
    return DENY;
  return IGNORE;
}

}  // namespace permission_broker
