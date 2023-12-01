// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/deny_claimed_hidraw_device_rule.h"

#include <gtest/gtest.h>
#include <libudev.h>

#include <string>

#include "base/strings/string_util.h"
#include "permission_broker/udev_scopers.h"

namespace permission_broker {

class DenyClaimedHidrawDeviceRuleTest : public testing::Test {
 public:
  DenyClaimedHidrawDeviceRuleTest() : udev_(udev_new()) {}
  DenyClaimedHidrawDeviceRuleTest(const DenyClaimedHidrawDeviceRuleTest&) =
      delete;
  DenyClaimedHidrawDeviceRuleTest& operator=(
      const DenyClaimedHidrawDeviceRuleTest&) = delete;

  ~DenyClaimedHidrawDeviceRuleTest() override = default;

 protected:
  ScopedUdevPtr udev_;
  DenyClaimedHidrawDeviceRule rule_;
};

TEST_F(DenyClaimedHidrawDeviceRuleTest, DenyClaimedHidrawDevices) {
  // Run the rule on every available device and verify that it only ignores
  // unclaimed USB HID devices, denying the rest.
  ScopedUdevEnumeratePtr enumerate(udev_enumerate_new(udev_.get()));
  udev_enumerate_add_match_subsystem(enumerate.get(), "hidraw");
  udev_enumerate_scan_devices(enumerate.get());
  struct udev_list_entry* entry = nullptr;
  udev_list_entry_foreach(entry,
                          udev_enumerate_get_list_entry(enumerate.get())) {
    const char* syspath = udev_list_entry_get_name(entry);
    ScopedUdevDevicePtr device(
        udev_device_new_from_syspath(udev_.get(), syspath));
    Rule::Result result = rule_.ProcessHidrawDevice(device.get());

    // This device was ignored by the rule. Make sure that it's a USB device
    // and that its USB interface is not, in fact, being used by other drivers.
    if (result == Rule::IGNORE) {
      struct udev_device* usb_interface =
          udev_device_get_parent_with_subsystem_devtype(device.get(), "usb",
                                                        "usb_interface");
      struct udev_device* hid_parent =
          udev_device_get_parent_with_subsystem_devtype(device.get(), "hid",
                                                        nullptr);

      ASSERT_NE(nullptr, hid_parent)
          << "We don't support hidraw devices with an HID parent.";

      std::string hid_parent_path(udev_device_get_syspath(hid_parent));
      std::string usb_interface_path;
      if (usb_interface)
        usb_interface_path.assign(udev_device_get_syspath(usb_interface));

      int hid_siblings = 0;
      bool should_sibling_subsystem_exclude_access = false;
      bool is_gamepad = false;
      // Verify that this hidraw device does not share a USB interface with any
      // other drivers' devices. This means we have to enumerate every device
      // to find any with the same ancestral usb_interface, then test for a non-
      // generic subsystem.
      ScopedUdevEnumeratePtr other_enumerate(udev_enumerate_new(udev_.get()));
      udev_enumerate_scan_devices(other_enumerate.get());
      struct udev_list_entry* other_entry = nullptr;
      udev_list_entry_foreach(
          other_entry, udev_enumerate_get_list_entry(other_enumerate.get())) {
        const char* other_path = udev_list_entry_get_name(other_entry);
        ScopedUdevDevicePtr other_device(
            udev_device_new_from_syspath(udev_.get(), other_path));
        struct udev_device* other_hid_parent =
            udev_device_get_parent_with_subsystem_devtype(other_device.get(),
                                                          "hid", nullptr);
        if (other_hid_parent) {
          std::string other_hid_parent_path(
              udev_device_get_syspath(other_hid_parent));
          if (hid_parent_path == other_hid_parent_path) {
            hid_siblings++;
          }
        }
        struct udev_device* other_usb_interface =
            udev_device_get_parent_with_subsystem_devtype(
                other_device.get(), "usb", "usb_interface");
        if (!other_usb_interface) {
          continue;
        }
        const char* devnode = udev_device_get_devnode(other_device.get());
        if (devnode != nullptr &&
            base::StartsWith(devnode, "/dev/input/js",
                             base::CompareCase::SENSITIVE)) {
          is_gamepad = true;
        }
        std::string other_usb_interface_path(
            udev_device_get_syspath(other_usb_interface));
        if (!should_sibling_subsystem_exclude_access &&
            usb_interface_path == other_usb_interface_path) {
          should_sibling_subsystem_exclude_access =
              DenyClaimedHidrawDeviceRule::
                  ShouldSiblingSubsystemExcludeHidAccess(other_device.get());
        }
      }
      ASSERT_FALSE(should_sibling_subsystem_exclude_access && !is_gamepad)
          << "This rule should IGNORE claimed devices.";
      ASSERT_FALSE(!usb_interface && hid_siblings > 1)
          << "This rule should DENY all non-USB HID devices.";

    } else if (result != Rule::DENY) {
      FAIL() << "This rule should only either IGNORE or DENY devices.";
    }
  }
}

TEST_F(DenyClaimedHidrawDeviceRuleTest, InputCapabilityExclusions) {
  const char* kKeyboardKeys;
  const char* kMouseKeys;
  const char* kHeadsetKeys;
  const char* kBrailleKeys;
  const char* kSpeakerphoneAbs;
  const char* kSpeakerphoneKeys;
  const char* kAbsoluteMouseAbs;
  const char* kAbsoluteMouseKeys;

  // The size of these bitfield chunks is the width of a userspace long.
  switch (sizeof(long)) {  // NOLINT(runtime/int)
    case 4:
      kKeyboardKeys =
          "10000 00000007 ff9f207a c14057ff "
          "febeffdf ffefffff ffffffff fffffffe";
      kMouseKeys = "1f0000 0 0 0 0 0 0 0 0";
      kHeadsetKeys = "18000 178 0 8e0000 0 0 0";
      kBrailleKeys = "7fe0000 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
      kSpeakerphoneAbs = "100 0";
      kSpeakerphoneKeys = "1 10000000 0 0 c0000000 0 0";
      kAbsoluteMouseAbs = "3";
      kAbsoluteMouseKeys = "70000 0 0 0 0 0 0 0 0";
      break;
    case 8:
      kKeyboardKeys =
          "1000000000007 ff9f207ac14057ff febeffdfffefffff fffffffffffffffe";
      kMouseKeys = "1f0000 0 0 0 0";
      kHeadsetKeys = "18000 17800000000 8e000000000000 0";
      kBrailleKeys = "7fe000000000000 0 0 0 0 0 0 0";
      kSpeakerphoneAbs = "10000000000";
      kSpeakerphoneKeys = "1 1000000000000000 0 c000000000000000 0";
      kAbsoluteMouseAbs = "3";
      kAbsoluteMouseKeys = "70000 0 0 0 0";
      break;
    default:
      FAIL() << "Unsupported platform long width.";
  }

  // Example capabilities from a real keyboard. Should be excluded.
  EXPECT_TRUE(
      DenyClaimedHidrawDeviceRule::ShouldInputCapabilitiesExcludeHidAccess(
          "0", "0", kKeyboardKeys));

  // Example capabilities from a real mouse. Should be excluded.
  EXPECT_TRUE(
      DenyClaimedHidrawDeviceRule::ShouldInputCapabilitiesExcludeHidAccess(
          "0", "103", kMouseKeys));

  // Example capabilities from a headset with some telephony buttons. Should not
  // be excluded.
  EXPECT_FALSE(
      DenyClaimedHidrawDeviceRule::ShouldInputCapabilitiesExcludeHidAccess(
          "0", "0", kHeadsetKeys));

  // A braille input device (made up). Should be excluded.
  EXPECT_TRUE(
      DenyClaimedHidrawDeviceRule::ShouldInputCapabilitiesExcludeHidAccess(
          "0", "0", kBrailleKeys));

  // Example capabilities from a speakerphone device which includes ABS_MISC
  // events. Should not be excluded.
  EXPECT_FALSE(
      DenyClaimedHidrawDeviceRule::ShouldInputCapabilitiesExcludeHidAccess(
          kSpeakerphoneAbs, "0", kSpeakerphoneKeys));

  // An absolute pointing device of the sort used by virtualization software.
  // Should be excluded.
  EXPECT_TRUE(
      DenyClaimedHidrawDeviceRule::ShouldInputCapabilitiesExcludeHidAccess(
          kAbsoluteMouseAbs, "0", kAbsoluteMouseKeys));
}

TEST_F(DenyClaimedHidrawDeviceRuleTest, JoystickCapabilitiesNotExcluded) {
  // Gamepad absolute capabilities (axes).
  const char* kDualAnalog8AxesAbs;
  const char* kDualAnalog6AxesNoHatAbs;
  const char* kDualAnalog6AxesAbs;
  const char* kDualshock3Abs;
  const char* kWiiUProAbs;
  const char* kSwitchProBluetoothAbs;

  // Gamepad key capabilities (buttons).
  const char* kXInputKeys;
  const char* kXboxOneBluetoothKeys;
  const char* kDualshock3Keys;
  const char* kDualshock4Keys;
  const char* kLogitechKeys;
  const char* kWiiUProKeys;
  const char* kSwitchProUsbKeys;
  const char* kSwitchProBluetoothKeys;

  // The size of these bitfield chunks is the width of a userspace long.
  switch (sizeof(long)) {  // NOLINT(runtime/int)
    case 4:
      kDualAnalog8AxesAbs = "3003f";
      kDualAnalog6AxesNoHatAbs = "3f";
      kDualAnalog6AxesAbs = "30027";
      kSwitchProBluetoothAbs = "3001b";
      kDualshock3Abs = "7fffff00 27";
      kWiiUProAbs = "1b";

      kXInputKeys = "7cdb0000 0 0 0 0 0 0 0 0 0";
      kXboxOneBluetoothKeys = "3ff0000 0 0 0 0 800 0 0 0 0";
      kDualshock3Keys = "7 0 0 0 0 0 0 0 0 0 0 0 0 ffff 0 0 0 0 0 0 0 0 0";
      kDualshock4Keys = "3fff0000 0 0 0 0 0 0 0 0 0";
      kLogitechKeys = "fff 0 0 0 0 0 0 0 0 0";
      kWiiUProKeys = "f 0 0 0 0 0 0 0 7fdb0000 0 0 0 0 0 0 0 0 0";
      kSwitchProUsbKeys = "3 0 0 0 0 0 0 0 0 0 0 0 0 ffff 0 0 0 0 0 0 0 0 0";
      kSwitchProBluetoothKeys = "ffff0000 0 0 0 0 0 0 0 0 0";
      break;
    case 8:
      kDualAnalog8AxesAbs = "3003f";
      kDualAnalog6AxesNoHatAbs = "3f";
      kDualAnalog6AxesAbs = "30027";
      kSwitchProBluetoothAbs = "3001b";
      kDualshock3Abs = "7fffff0000000027";
      kWiiUProAbs = "1b";

      kXInputKeys = "7cdb000000000000 0 0 0 0";
      kXboxOneBluetoothKeys = "3ff000000000000 0 800 0 0";
      kDualshock3Keys = "7 0 0 0 0 0 0 ffff00000000 0 0 0 0";
      kDualshock4Keys = "3fff000000000000 0 0 0 0";
      kLogitechKeys = "fff00000000 0 0 0 0";
      kWiiUProKeys = "f00000000 0 0 0 7fdb000000000000 0 0 0 0";
      kSwitchProUsbKeys = "3 0 0 0 0 0 0 ffff00000000 0 0 0 0";
      kSwitchProBluetoothKeys = "ffff000000000000 0 0 0 0";
      break;
    default:
      FAIL() << "Unsupported platform long width.";
  }

  // XInput gamepad.
  EXPECT_FALSE(
      DenyClaimedHidrawDeviceRule::ShouldInputCapabilitiesExcludeHidAccess(
          kDualAnalog8AxesAbs, "0", kXInputKeys));

  // Xbox One S gamepad connected over Bluetooth.
  EXPECT_FALSE(
      DenyClaimedHidrawDeviceRule::ShouldInputCapabilitiesExcludeHidAccess(
          kDualAnalog8AxesAbs, "0", kXboxOneBluetoothKeys));

  // Dualshock4 gamepad connected over USB.
  EXPECT_FALSE(
      DenyClaimedHidrawDeviceRule::ShouldInputCapabilitiesExcludeHidAccess(
          kDualAnalog8AxesAbs, "0", kDualshock4Keys));

  // Logitech F310 gamepad in DirectInput mode.
  EXPECT_FALSE(
      DenyClaimedHidrawDeviceRule::ShouldInputCapabilitiesExcludeHidAccess(
          kDualAnalog6AxesAbs, "0", kLogitechKeys));

  // Wii U Pro gamepad connected over Bluetooth.
  EXPECT_FALSE(
      DenyClaimedHidrawDeviceRule::ShouldInputCapabilitiesExcludeHidAccess(
          kWiiUProAbs, "0", kWiiUProKeys));

  // Switch Pro gamepad connected over USB.
  EXPECT_FALSE(
      DenyClaimedHidrawDeviceRule::ShouldInputCapabilitiesExcludeHidAccess(
          kDualAnalog6AxesAbs, "0", kSwitchProUsbKeys));

  // Switch Pro gamepad connected over Bluetooth.
  EXPECT_FALSE(
      DenyClaimedHidrawDeviceRule::ShouldInputCapabilitiesExcludeHidAccess(
          kSwitchProBluetoothAbs, "0", kSwitchProBluetoothKeys));

  // Dualshock3 gamepad connected over USB.
  // TODO(crbug.com/840004) This returns true because Dualshock3 exposes
  // absolute inputs outside the range normally used by gamepads.
  EXPECT_TRUE(
      DenyClaimedHidrawDeviceRule::ShouldInputCapabilitiesExcludeHidAccess(
          kDualshock3Abs, "0", kDualshock3Keys));

  // A Dualshock3-like gamepad with more typical axes.
  EXPECT_FALSE(
      DenyClaimedHidrawDeviceRule::ShouldInputCapabilitiesExcludeHidAccess(
          kDualAnalog6AxesNoHatAbs, "0", kDualshock3Keys));
}

}  // namespace permission_broker
