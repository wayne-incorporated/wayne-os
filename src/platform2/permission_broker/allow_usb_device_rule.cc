// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/allow_usb_device_rule.h"

#include <libudev.h>

namespace permission_broker {

AllowUsbDeviceRule::AllowUsbDeviceRule()
    : UsbSubsystemUdevRule("AllowUsbDeviceRule") {}

Rule::Result AllowUsbDeviceRule::ProcessUsbDevice(struct udev_device* device) {
  return ALLOW;
}

}  // namespace permission_broker
