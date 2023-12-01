// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/deny_unsafe_hidraw_device_rule.h"

#include <libudev.h>

#include <vector>

#include "permission_broker/rule_utils.h"

namespace permission_broker {

namespace {

bool IsKeyboardUsage(const HidUsage& usage) {
  if (usage.page == HidUsage::PAGE_KEYBOARD)
    return true;

  if (usage.page == HidUsage::PAGE_GENERIC_DESKTOP) {
    return usage.usage == HidUsage::GENERIC_DESKTOP_USAGE_KEYBOARD ||
           usage.usage == HidUsage::GENERIC_DESKTOP_USAGE_KEYPAD;
  }

  return false;
}

bool IsPointerUsage(const HidUsage& usage) {
  if (usage.page == HidUsage::PAGE_GENERIC_DESKTOP) {
    return usage.usage == HidUsage::GENERIC_DESKTOP_USAGE_POINTER ||
           usage.usage == HidUsage::GENERIC_DESKTOP_USAGE_MOUSE;
  }
  return false;
}

bool IsSystemControlUsage(const HidUsage& usage) {
  if (usage.page != HidUsage::PAGE_GENERIC_DESKTOP)
    return false;
  if (usage.usage >= HidUsage::GENERIC_DESKTOP_USAGE_SYSTEM_CONTROL &&
      usage.usage <= HidUsage::GENERIC_DESKTOP_USAGE_SYSTEM_WARM_RESTART) {
    return true;
  }
  if (usage.usage >= HidUsage::GENERIC_DESKTOP_USAGE_SYSTEM_DOCK &&
      usage.usage <= HidUsage::GENERIC_DESKTOP_USAGE_SYSTEM_DISPLAY_SWAP) {
    return true;
  }
  return false;
}

}  // namespace

DenyUnsafeHidrawDeviceRule::DenyUnsafeHidrawDeviceRule()
    : HidrawSubsystemUdevRule("DenyUnsafeHidrawDeviceRule") {}

Rule::Result DenyUnsafeHidrawDeviceRule::ProcessHidrawDevice(
    struct udev_device* device) {
  std::vector<HidUsage> usages;
  if (!GetHidToplevelUsages(device, &usages)) {
    return IGNORE;
  }

  // Ignore devices which are known to be safe and should work with WebHID.
  struct udev_device* usb_device =
      udev_device_get_parent_with_subsystem_devtype(device, "usb",
                                                    "usb_device");
  if (usb_device && IsDeviceAllowedWebHID(usb_device))
    return IGNORE;

  for (std::vector<HidUsage>::const_iterator iter = usages.begin();
       iter != usages.end(); ++iter) {
    if (IsUnsafeUsage(*iter)) {
      return DENY;
    }
  }
  return IGNORE;
}

// static
bool DenyUnsafeHidrawDeviceRule::IsUnsafeUsage(const HidUsage& usage) {
  return IsKeyboardUsage(usage) || IsPointerUsage(usage) ||
         IsSystemControlUsage(usage);
}

}  // namespace permission_broker
