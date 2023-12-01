// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/deny_hammer_device_rule.h"

#include <libudev.h>

#include <iterator>

#include <base/strings/string_number_conversions.h>

#include "permission_broker/rule_utils.h"
#include "policy/device_policy.h"

using policy::DevicePolicy;

namespace permission_broker {

namespace {

bool IsHammerDevice(udev_device* device) {
  const DevicePolicy::UsbDeviceId kHammerIds[] = {
      {0x18d1, 0x5022},  // hammer
      {0x18d1, 0x502b},  // staff
      {0x18d1, 0x502d},  // wand
      {0x18d1, 0x5030},  // whiskers
      {0x18d1, 0x503c},  // masterball
      {0x18d1, 0x503d},  // magnemite
      {0x18d1, 0x5044},  // moonball
      {0x18d1, 0x504c},  // zed
      {0x18d1, 0x5050},  // don
      {0x18d1, 0x5052},  // star
      {0x18d1, 0x5056},  // bland
      {0x18d1, 0x5057},  // eel
      {0x18d1, 0x505b},  // duck
      {0x18d1, 0x505d},  // gelatin
  };
  uint32_t vendor_id, product_id;
  GetUIntSysattr(device, "idVendor", &vendor_id);
  GetUIntSysattr(device, "idProduct", &product_id);

  return UsbDeviceListContainsId(std::begin(kHammerIds), std::end(kHammerIds),
                                 vendor_id, product_id);
}

}  // namespace

DenyHammerDeviceRule::DenyHammerDeviceRule()
    : UsbSubsystemUdevRule("DenyHammerDeviceRule") {}

Rule::Result DenyHammerDeviceRule::ProcessUsbDevice(
    struct udev_device* device) {
  if (IsHammerDevice(device)) {
    return DENY;
  }

  // Not a hammer, pass through IGNORE.
  return IGNORE;
}

}  // namespace permission_broker
