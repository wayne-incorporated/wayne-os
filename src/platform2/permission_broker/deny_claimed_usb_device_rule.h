// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_DENY_CLAIMED_USB_DEVICE_RULE_H_
#define PERMISSION_BROKER_DENY_CLAIMED_USB_DEVICE_RULE_H_

#include <vector>

#include "permission_broker/usb_subsystem_udev_rule.h"
#include "policy/device_policy.h"
#include "policy/libpolicy.h"

struct udev;

namespace permission_broker {

// DenyClaimedUsbDeviceRule encapsulates the policy that any USB device that is
// claimed by a driver is |DENY|'d, while all other requests are |IGNORE|'d. It
// does this by walking the udev device tree (the entire tree, not just the USB
// subsystem) and attempts, for each device entry, to find a parent device
// within the USB subsystem whose device node property is the same as the |path|
// parameter. If such a matching device exists, the path is rejected as it has
// been demonstrated to be claimed by another udev entry.
// Android devices with USB debugging enabled may have an unclaimed interface
// for ADB but other claimed interfaces for e.g. mass storage. In this case,
// we can allow access even if there are claimed interfaces, though we'll detach
// first.
class DenyClaimedUsbDeviceRule : public UsbSubsystemUdevRule {
 public:
  DenyClaimedUsbDeviceRule();
  DenyClaimedUsbDeviceRule(const DenyClaimedUsbDeviceRule&) = delete;
  DenyClaimedUsbDeviceRule& operator=(const DenyClaimedUsbDeviceRule&) = delete;

  ~DenyClaimedUsbDeviceRule() override;

  Result ProcessUsbDevice(udev_device* device) override;

 protected:
  std::vector<policy::DevicePolicy::UsbDeviceId> usb_allow_list_;

 private:
  bool policy_loaded_;

  // Loads the device settings policy and returns success.
  virtual bool LoadPolicy();

  // Returns whether a USB device is allowed inside the device settings
  // to be detached from its kernel driver.
  bool IsDeviceDetachableByPolicy(udev_device* device);

  // Returns whether a USB interface represents the Android Debug Bridge.
  // If so, then its parent node is an Android device with USB debugging
  // enabled and we can detach its other interfaces to use it.
  bool IsInterfaceAdb(udev_device* device);
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_DENY_CLAIMED_USB_DEVICE_RULE_H_
