// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/deny_claimed_hidraw_device_rule.h"

#include <bits/wordsize.h>
#include <libudev.h>
#include <linux/input.h>

#include <algorithm>
#include <limits>
#include <string>
#include <vector>

#include "base/containers/adapters.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "permission_broker/rule_utils.h"
#include "permission_broker/udev_scopers.h"

namespace permission_broker {

namespace {

const std::vector<std::string> kGenericSubsystems = {
    "bluetooth", "hid", "hidraw", "rfkill", "usb", "usbmisc"};

const char kLogitechUnifyingReceiverDriver[] = "logitech-djreceiver";
const char kThingmDriver[] = "thingm";

const base::StringPiece kJoydevPrefix = "/dev/input/js";

const size_t kAllowedAbsCapabilities[] = {
    ABS_X,     ABS_Y,        ABS_Z,      ABS_RX,    ABS_RY,
    ABS_RZ,    ABS_THROTTLE, ABS_RUDDER, ABS_WHEEL, ABS_GAS,
    ABS_BRAKE, ABS_HAT0X,    ABS_HAT0Y,  ABS_HAT1X, ABS_HAT1Y,
    ABS_HAT2X, ABS_HAT2Y,    ABS_HAT3X,  ABS_HAT3Y, ABS_MISC,
};

bool ParseInputCapabilities(const char* input, std::vector<uint64_t>* output) {
  // The kernel expresses capabilities as a bitfield, broken into long-sized
  // chunks encoded in hexadecimal.
  std::vector<std::string> chunks = base::SplitString(
      input, " ", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);

  output->clear();
  output->reserve(chunks.size());

  // The most-significant chunk of the bitmask is stored first, iterate over
  // the chunks in reverse so that the result is easier to work with.
  for (const std::string& chunk : base::Reversed(chunks)) {
    uint64_t value = 0;
    if (!base::HexStringToUInt64(chunk, &value)) {
      LOG(ERROR) << "Failed to parse: " << chunk;
      return false;
    }
    // NOLINTNEXTLINE(runtime/int)
    if (value > std::numeric_limits<unsigned long>::max()) {
      LOG(ERROR) << "Chunk value too large for platform: " << value;
      return false;
    }
    output->push_back(value);
  }

  if (__WORDSIZE == 32) {
    // Compact the vector of 32-bit values into a vector of 64-bit values.
    for (size_t i = 0; i < chunks.size(); i += 2) {
      (*output)[i / 2] = (*output)[i];
      if (i + 1 < chunks.size())
        (*output)[i / 2] |= (uint64_t)((*output)[i + 1]) << 32;
    }
    output->resize((chunks.size() + 1) / 2);
  }

  return true;
}

bool IsCapabilityBitSet(const std::vector<uint64_t>& bitfield, size_t bit) {
  size_t offset = bit / (sizeof(uint64_t) * 8);
  if (offset >= bitfield.size())
    return false;

  return bitfield[offset] & (1ULL << (bit - offset * sizeof(bitfield[0]) * 8));
}

bool AnyCapabilityBitsSet(const std::vector<uint64_t>& bitfield) {
  for (auto value : bitfield) {
    if (value != 0)
      return true;
  }
  return false;
}

void UnsetCapabilityBit(std::vector<uint64_t>* bitfield, size_t bit) {
  size_t offset = bit / (sizeof(uint64_t) * 8);
  if (offset >= bitfield->size())
    return;

  (*bitfield)[offset] &= ~(1ULL << (bit - offset * sizeof(uint64_t) * 8));
}

// Joydev devices expose a devnode string with the format:
//     /dev/input/js#
// Where # is the numeric index of the joydev device.
bool IsJoydevDeviceNode(base::StringPiece devnode) {
  // Match the devnode prefix.
  if (!base::StartsWith(devnode, kJoydevPrefix, base::CompareCase::SENSITIVE))
    return false;

  // Match if the suffix parses as a non-negative integer.
  devnode.remove_prefix(kJoydevPrefix.length());
  int joydev_index = 0;
  if (!base::StringToInt(devnode, &joydev_index))
    return false;
  return joydev_index >= 0;
}

}  // namespace

DenyClaimedHidrawDeviceRule::DenyClaimedHidrawDeviceRule()
    : HidrawSubsystemUdevRule("DenyClaimedHidrawDeviceRule") {}

Rule::Result DenyClaimedHidrawDeviceRule::ProcessHidrawDevice(
    struct udev_device* device) {
  struct udev_device* hid_parent =
      udev_device_get_parent_with_subsystem_devtype(device, "hid", nullptr);
  if (!hid_parent) {
    // A hidraw device without a HID parent, we don't know what this can be.
    return DENY;
  }

  const char* hid_parent_driver = udev_device_get_driver(hid_parent);
  if (hid_parent_driver) {
    // Add an exception to the rule for Logitech Unifying receiver. This hidraw
    // device is a parent of devices that have input subsystem. Yet the traffic
    // to those children is not available on the hidraw node of the receiver,
    // so it is safe to allow it.
    if (strcmp(hid_parent_driver, kLogitechUnifyingReceiverDriver) == 0) {
      LOG(INFO) << "Found Logitech Unifying receiver. Skipping rule.";
      return IGNORE;
    }

    // An led subsystem driver is provided for this device but for historical
    // reasons we want to continue to allow raw HID access as well.
    if (strcmp(hid_parent_driver, kThingmDriver) == 0) {
      LOG(INFO) << "Found ThingM blink(1). Skipping rule.";
      return IGNORE;
    }
  }

  std::string hid_parent_path(udev_device_get_syspath(hid_parent));
  std::string usb_interface_path;
  struct udev_device* usb_interface =
      udev_device_get_parent_with_subsystem_devtype(device, "usb",
                                                    "usb_interface");

  if (usb_interface)
    usb_interface_path = udev_device_get_syspath(usb_interface);

  // Ignore devices which are known to be safe and should work with WebHID.
  struct udev_device* usb_device =
      udev_device_get_parent_with_subsystem_devtype(device, "usb",
                                                    "usb_device");
  if (usb_device && IsDeviceAllowedWebHID(usb_device))
    return IGNORE;

  // Count the number of children of the same HID parent as us.
  int hid_siblings = 0;

  bool should_sibling_subsystem_exclude_access = false;

  // Scan all children of the USB interface for subsystems other than generic
  // USB or HID, and all the children of the same HID parent device.
  // The presence of such subsystems is an indication that the device is in
  // use by another driver.
  //
  // Because udev lacks the ability to filter an enumeration by arbitrary
  // ancestor properties (e.g. "enumerate all nodes with a usb_interface
  // ancestor") we have to scan the entire set of devices to find potential
  // matches.
  struct udev* udev = udev_device_get_udev(device);
  ScopedUdevEnumeratePtr enumerate(udev_enumerate_new(udev));
  udev_enumerate_scan_devices(enumerate.get());
  struct udev_list_entry* entry;
  udev_list_entry_foreach(entry,
                          udev_enumerate_get_list_entry(enumerate.get())) {
    const char* syspath = udev_list_entry_get_name(entry);
    ScopedUdevDevicePtr child(udev_device_new_from_syspath(udev, syspath));
    struct udev_device* child_usb_interface =
        udev_device_get_parent_with_subsystem_devtype(child.get(), "usb",
                                                      "usb_interface");
    struct udev_device* child_hid_parent =
        udev_device_get_parent_with_subsystem_devtype(child.get(), "hid",
                                                      nullptr);
    if (!child_usb_interface && !child_hid_parent) {
      continue;
    }
    // Some gamepads expose functionality that is only accessible through the
    // hidraw node. To allow hidraw access to such devices, skip the sibling
    // subsystem and capabilities checks if one of the siblings is a joydev
    // device.
    const char* devnode = udev_device_get_devnode(child.get());
    if (devnode && IsJoydevDeviceNode(devnode))
      return IGNORE;

    // This device shares a USB interface with the hidraw device in question.
    // Check its subsystem to see if it should block hidraw access.
    if (!should_sibling_subsystem_exclude_access && usb_interface &&
        child_usb_interface &&
        usb_interface_path == udev_device_get_syspath(child_usb_interface)) {
      should_sibling_subsystem_exclude_access =
          ShouldSiblingSubsystemExcludeHidAccess(child.get());
    }
    // This device shares the same HID device as parent, count it.
    if (child_hid_parent &&
        hid_parent_path == udev_device_get_syspath(child_hid_parent)) {
      hid_siblings++;
    }
  }

  // If the underlying device presents other interfaces, deny access to the
  // hidraw node as it may allow access to private data transmitted over these
  // interfaces.
  if (should_sibling_subsystem_exclude_access)
    return DENY;

  // If the underlying HID device presents no other interface than hidraw,
  // we can use it.
  // USB devices have already been filtered directly in the loop above.
  if (!usb_interface && hid_siblings != 1)
    return DENY;

  return IGNORE;
}

bool DenyClaimedHidrawDeviceRule::ShouldSiblingSubsystemExcludeHidAccess(
    struct udev_device* sibling) {
  const char* subsystem = udev_device_get_subsystem(sibling);
  if (!subsystem) {
    return false;
  }

  // Generic subsystems (such as "hid" or "usb") should never exclude access.
  if (std::find(kGenericSubsystems.begin(), kGenericSubsystems.end(),
                subsystem) != kGenericSubsystems.end()) {
    return false;
  }

  // Don't block hidraw access due to leds subsystem.
  if (strcmp(subsystem, "leds") == 0) {
    return false;
  }

  if (strcmp(subsystem, "input") == 0 &&
      !ShouldInputCapabilitiesExcludeHidAccess(
          udev_device_get_sysattr_value(sibling, "capabilities/abs"),
          udev_device_get_sysattr_value(sibling, "capabilities/rel"),
          udev_device_get_sysattr_value(sibling, "capabilities/key"))) {
    return false;
  }

  return true;
}

bool DenyClaimedHidrawDeviceRule::ShouldInputCapabilitiesExcludeHidAccess(
    const char* abs_capabilities,
    const char* rel_capabilities,
    const char* key_capabilities) {
  bool has_absolute_mouse_axes = false;
  bool has_absolute_mouse_keys = false;
  std::vector<uint64_t> capabilities;
  if (abs_capabilities) {
    if (!ParseInputCapabilities(abs_capabilities, &capabilities)) {
      // Parse error? Fail safe.
      return true;
    }

    // If the device has ABS_X and ABS_Y and no other absolute axes, it may be
    // an absolute pointing device.
    if (IsCapabilityBitSet(capabilities, ABS_X) &&
        IsCapabilityBitSet(capabilities, ABS_Y)) {
      UnsetCapabilityBit(&capabilities, ABS_X);
      UnsetCapabilityBit(&capabilities, ABS_Y);
      if (!AnyCapabilityBitsSet(capabilities))
        has_absolute_mouse_axes = true;
    }

    // Remove allowed capabilities. Any other absolute pointer capabilities
    // exclude access.
    for (const auto& abs_capabilities : kAllowedAbsCapabilities)
      UnsetCapabilityBit(&capabilities, abs_capabilities);
    if (AnyCapabilityBitsSet(capabilities))
      return true;
  }

  if (rel_capabilities) {
    if (!ParseInputCapabilities(rel_capabilities, &capabilities)) {
      // Parse error? Fail safe.
      return true;
    }
    // Any relative pointer capabilities exclude access.
    if (AnyCapabilityBitsSet(capabilities))
      return true;
  }

  if (key_capabilities) {
    if (!ParseInputCapabilities(key_capabilities, &capabilities)) {
      // Parse error? Fail safe.
      return true;
    }

    // If the device has BTN_LEFT, BTN_RIGHT, BTN_MIDDLE and no other keys,
    // it may be an absolute pointing device.
    if (IsCapabilityBitSet(capabilities, BTN_LEFT) &&
        IsCapabilityBitSet(capabilities, BTN_RIGHT) &&
        IsCapabilityBitSet(capabilities, BTN_MIDDLE)) {
      UnsetCapabilityBit(&capabilities, BTN_LEFT);
      UnsetCapabilityBit(&capabilities, BTN_RIGHT);
      UnsetCapabilityBit(&capabilities, BTN_MIDDLE);
      if (!AnyCapabilityBitsSet(capabilities))
        has_absolute_mouse_keys = true;
    }

    // Any key code <= KEY_KPDOT (83) excludes access.
    for (int key = 0; key <= KEY_KPDOT; key++) {
      if (IsCapabilityBitSet(capabilities, key)) {
        return true;
      }
    }
    // Braille dots are outside the "normal keyboard keys" range.
    for (int key = KEY_BRL_DOT1; key <= KEY_BRL_DOT10; key++) {
      if (IsCapabilityBitSet(capabilities, key)) {
        return true;
      }
    }
  }

  // Exclude absolute pointing devices that match joydev's capabilities check.
  if (has_absolute_mouse_axes && has_absolute_mouse_keys)
    return true;

  return false;
}

}  // namespace permission_broker
