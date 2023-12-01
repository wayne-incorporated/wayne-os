// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/usb_subsystem_udev_rule.h"

#include <libudev.h>
#include <string.h>

#include <string>

using std::string;

namespace permission_broker {

UsbSubsystemUdevRule::UsbSubsystemUdevRule(const string& name) : Rule(name) {}

Rule::Result UsbSubsystemUdevRule::ProcessDevice(struct udev_device* device) {
  const char* const subsystem = udev_device_get_subsystem(device);
  if (!subsystem || strcmp(subsystem, "usb"))
    return IGNORE;
  return ProcessUsbDevice(device);
}

}  // namespace permission_broker
