// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/input_device_controller.h"

#include <cstdarg>

#include <gtest/gtest.h>

#include "power_manager/common/fake_prefs.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/policy/backlight_controller_stub.h"
#include "power_manager/powerd/system/acpi_wakeup_helper_stub.h"
#include "power_manager/powerd/system/cros_ec_helper_stub.h"
#include "power_manager/powerd/system/udev_stub.h"
#include "power_manager/powerd/testing/test_environment.h"
#include "power_manager/proto_bindings/backlight.pb.h"

namespace power_manager::policy {

namespace {
// An artificial syspath for tests.
const char kSyspath0[] = "/sys/devices/test/0";

// Create aliases for lengthy constant names.
const char* const kTagInhibit = InputDeviceController::kTagInhibit;
const char* const kTagUsableWhenDocked =
    InputDeviceController::kTagUsableWhenDocked;
const char* const kTagUsableWhenDisplayOff =
    InputDeviceController::kTagUsableWhenDisplayOff;
const char* const kTagUsableWhenLaptop =
    InputDeviceController::kTagUsableWhenLaptop;
const char* const kTagUsableWhenTablet =
    InputDeviceController::kTagUsableWhenTablet;
const char* const kTagWakeup = InputDeviceController::kTagWakeup;
const char* const kTagWakeupWhenLaptop =
    InputDeviceController::kTagWakeupWhenLaptop;
const char* const kTagWakeupOnlyWhenUsable =
    InputDeviceController::kTagWakeupOnlyWhenUsable;
const char* const kTagWakeupDisabled =
    InputDeviceController::kTagWakeupDisabled;
const char* const kEnabled = InputDeviceController::kWakeupEnabled;
const char* const kDisabled = InputDeviceController::kWakeupDisabled;
const char* const kInhibited = InputDeviceController::kInhibited;
const char* const kTPAD = InputDeviceController::kTPAD;
const char* const kTSCR = InputDeviceController::kTSCR;

}  // namespace

class InputDeviceControllerTest : public TestEnvironment {
 public:
  InputDeviceControllerTest() = default;
  InputDeviceControllerTest(const InputDeviceControllerTest&) = delete;
  InputDeviceControllerTest& operator=(const InputDeviceControllerTest&) =
      delete;

  ~InputDeviceControllerTest() override = default;

 protected:
  std::string GetSysattr(const std::string& syspath,
                         const std::string& sysattr) {
    std::string value;
    if (!udev_.GetSysattr(syspath, sysattr, &value))
      return "(error)";
    return value;
  }

  bool GetAcpiWakeup(const std::string& acpi_name) {
    bool value = false;
    if (!acpi_wakeup_helper_.GetWakeupEnabled(acpi_name, &value)) {
      ADD_FAILURE() << "Expected ACPI wakeup for " << acpi_name
                    << " to be defined";
    }
    return value;
  }

  // Adds a device at |syspath| with one or more udev tags. The tag list must be
  // null-terminated.
  void AddDeviceWithTags(const std::string& syspath, const char* tag, ...) {
    udev_.SetSysattr(syspath, kPowerWakeup, kDisabled);

    std::string tags;
    va_list arg_list;
    va_start(arg_list, tag);
    while (tag) {
      if (!tags.empty())
        tags += " ";
      tags += tag;
      tag = va_arg(arg_list, const char*);
    }
    va_end(arg_list);

    udev_.TaggedDeviceChanged(syspath, base::FilePath(syspath), tags);
  }

  void InitInputDeviceController() {
    input_device_controller_.Init(&backlight_controller_, &udev_,
                                  &acpi_wakeup_helper_, &ec_helper_,
                                  initial_lid_state_, initial_tablet_mode_,
                                  initial_display_mode_, &prefs_);
  }

  policy::BacklightControllerStub backlight_controller_;
  system::UdevStub udev_;
  system::AcpiWakeupHelperStub acpi_wakeup_helper_;
  system::CrosEcHelperStub ec_helper_;
  FakePrefs prefs_;

  LidState initial_lid_state_ = LidState::OPEN;
  TabletMode initial_tablet_mode_ = TabletMode::OFF;
  DisplayMode initial_display_mode_ = DisplayMode::NORMAL;

  InputDeviceController input_device_controller_;
};

TEST_F(InputDeviceControllerTest, ConfigureWakeupOnInit) {
  AddDeviceWithTags(kSyspath0, kTagWakeup, nullptr);

  EXPECT_EQ(kDisabled, GetSysattr(kSyspath0, kPowerWakeup));
  InitInputDeviceController();
  EXPECT_EQ(kEnabled, GetSysattr(kSyspath0, kPowerWakeup));
  EXPECT_TRUE(GetAcpiWakeup(kTPAD));
  EXPECT_FALSE(GetAcpiWakeup(kTSCR));
}

TEST_F(InputDeviceControllerTest, ConfigureWakeupOnAdd) {
  InitInputDeviceController();

  // The device starts out with wakeup disabled, but should get configured by
  // InputDeviceController right away.
  AddDeviceWithTags(kSyspath0, kTagWakeup, nullptr);
  EXPECT_EQ(kEnabled, GetSysattr(kSyspath0, kPowerWakeup));
}

TEST_F(InputDeviceControllerTest, DisableWakeupWhenClosed) {
  AddDeviceWithTags(kSyspath0, kTagWakeup, kTagWakeupOnlyWhenUsable,
                    kTagUsableWhenLaptop, nullptr);
  InitInputDeviceController();

  // In laptop mode, wakeup should be enabled.
  EXPECT_EQ(kEnabled, GetSysattr(kSyspath0, kPowerWakeup));
  EXPECT_TRUE(GetAcpiWakeup("TPAD"));

  // When the lid is closed, wakeup should be disabled.
  input_device_controller_.SetLidState(LidState::CLOSED);
  EXPECT_EQ(kDisabled, GetSysattr(kSyspath0, kPowerWakeup));
  EXPECT_FALSE(GetAcpiWakeup(kTPAD));
}

TEST_F(InputDeviceControllerTest, PermanentlyDisableWakeup) {
  AddDeviceWithTags(kSyspath0, kTagWakeup, kTagWakeupDisabled, nullptr);

  // Simulate a device that has wakeup enabled initially.
  udev_.SetSysattr(kSyspath0, kPowerWakeup, kEnabled);
  InitInputDeviceController();
  EXPECT_EQ(kDisabled, GetSysattr(kSyspath0, kPowerWakeup));
}

TEST_F(InputDeviceControllerTest, ConfigureInhibit) {
  AddDeviceWithTags(kSyspath0, kTagInhibit, kTagUsableWhenLaptop, nullptr);
  InitInputDeviceController();

  // In laptop mode, inhibit should be off.
  EXPECT_EQ("0", GetSysattr(kSyspath0, kInhibited));

  // When the lid is closed, inhibit should be on.
  input_device_controller_.SetLidState(LidState::CLOSED);
  EXPECT_EQ("1", GetSysattr(kSyspath0, kInhibited));

  // When the lid is open, inhibit should be off again.
  input_device_controller_.SetLidState(LidState::OPEN);
  EXPECT_EQ("0", GetSysattr(kSyspath0, kInhibited));
}

TEST_F(InputDeviceControllerTest, InhibitDocking) {
  AddDeviceWithTags(kSyspath0, kTagInhibit, kTagUsableWhenLaptop,
                    kTagUsableWhenDocked, nullptr);
  initial_display_mode_ = DisplayMode::PRESENTATION;
  InitInputDeviceController();

  // In laptop mode, inhibit should be off.
  EXPECT_EQ("0", GetSysattr(kSyspath0, kInhibited));

  // When the lid is closed, inhibit should remain off.
  input_device_controller_.SetLidState(LidState::CLOSED);
  EXPECT_EQ("0", GetSysattr(kSyspath0, kInhibited));

  // When the lid is open, inhibit should still be off.
  input_device_controller_.SetLidState(LidState::OPEN);
  EXPECT_EQ("0", GetSysattr(kSyspath0, kInhibited));
}

TEST_F(InputDeviceControllerTest, SetDisplayModeExternalInput) {
  AddDeviceWithTags(kSyspath0, kTagInhibit, kTagUsableWhenLaptop,
                    kTagUsableWhenDocked, nullptr);
  initial_lid_state_ = LidState::CLOSED;
  InitInputDeviceController();

  // When the lid is closed with no external display, external input devices
  // should be inhibited.
  EXPECT_EQ("1", GetSysattr(kSyspath0, kInhibited));

  // When an external display is attached, device should be un-inhibited.
  input_device_controller_.SetDisplayMode(DisplayMode::PRESENTATION);
  EXPECT_EQ("0", GetSysattr(kSyspath0, kInhibited));

  // When external display goes away, input should be inhibited again.
  input_device_controller_.SetDisplayMode(DisplayMode::NORMAL);
  EXPECT_EQ("1", GetSysattr(kSyspath0, kInhibited));
}

TEST_F(InputDeviceControllerTest, SetDisplayModeInternalInput) {
  AddDeviceWithTags(kSyspath0, kTagInhibit, kTagUsableWhenLaptop, nullptr);
  InitInputDeviceController();

  // Devices that are only usable when in laptop mode should not be inhibited
  // while the lid is open.
  EXPECT_EQ("0", GetSysattr(kSyspath0, kInhibited));

  // When an external display is attached, device should remain uninhibited.
  input_device_controller_.SetDisplayMode(DisplayMode::PRESENTATION);
  EXPECT_EQ("0", GetSysattr(kSyspath0, kInhibited));

  // When the lid is closed, internal input should be inhibited regardless
  // of display mode.
  input_device_controller_.SetLidState(LidState::CLOSED);
  EXPECT_EQ("1", GetSysattr(kSyspath0, kInhibited));

  input_device_controller_.SetDisplayMode(DisplayMode::NORMAL);
  EXPECT_EQ("1", GetSysattr(kSyspath0, kInhibited));
}

TEST_F(InputDeviceControllerTest, AllowEcWakeupAsTabletWhenDisplayOff) {
  InitInputDeviceController();

  // Start in presentation mode at full brightness.
  input_device_controller_.SetDisplayMode(DisplayMode::PRESENTATION);
  backlight_controller_.NotifyObservers(
      100.0, BacklightBrightnessChange_Cause_USER_REQUEST);

  // EC wakeups should be inhibited in tablet mode while backlight is on.
  EXPECT_FALSE(ec_helper_.IsWakeupAsTabletAllowed());

  // Automated display off should not trigger a mode change.
  backlight_controller_.NotifyObservers(
      0.0, BacklightBrightnessChange_Cause_USER_INACTIVITY);
  EXPECT_FALSE(ec_helper_.IsWakeupAsTabletAllowed());

  // ...but manual should.
  backlight_controller_.NotifyObservers(
      0.0, BacklightBrightnessChange_Cause_USER_REQUEST);
  EXPECT_TRUE(ec_helper_.IsWakeupAsTabletAllowed());

  // Leaving presentation mode should disallow it.
  input_device_controller_.SetDisplayMode(DisplayMode::NORMAL);
  EXPECT_FALSE(ec_helper_.IsWakeupAsTabletAllowed());
  input_device_controller_.SetDisplayMode(DisplayMode::PRESENTATION);
  EXPECT_TRUE(ec_helper_.IsWakeupAsTabletAllowed());

  // As should raising the brightness, even if automatic.
  backlight_controller_.NotifyObservers(10.0,
                                        BacklightBrightnessChange_Cause_OTHER);
  EXPECT_FALSE(ec_helper_.IsWakeupAsTabletAllowed());
}

TEST_F(InputDeviceControllerTest, HandleTabletMode) {
  const char kKeyboardSyspath[] = "/sys/devices/keyboard/0";
  const char kTouchscreenSyspath[] = "/sys/devices/touchscreen/0";
  AddDeviceWithTags(kKeyboardSyspath, kTagInhibit, kTagWakeup,
                    kTagWakeupOnlyWhenUsable, kTagUsableWhenLaptop,
                    kTagUsableWhenDisplayOff, nullptr);
  AddDeviceWithTags(kTouchscreenSyspath, kTagInhibit, kTagWakeup,
                    kTagWakeupOnlyWhenUsable, kTagUsableWhenLaptop,
                    kTagUsableWhenTablet, nullptr);
  initial_tablet_mode_ = TabletMode::ON;

  // While in tablet mode, the keyboard should be inhibited with wakeup
  // disabled.
  InitInputDeviceController();
  EXPECT_EQ("1", GetSysattr(kKeyboardSyspath, kInhibited));
  EXPECT_EQ(kDisabled, GetSysattr(kKeyboardSyspath, kPowerWakeup));
  EXPECT_EQ("0", GetSysattr(kTouchscreenSyspath, kInhibited));
  EXPECT_EQ(kEnabled, GetSysattr(kTouchscreenSyspath, kPowerWakeup));

  // Switching to laptop mode should uninhibit the keyboard and permit wakeups.
  input_device_controller_.SetTabletMode(TabletMode::OFF);
  EXPECT_EQ("0", GetSysattr(kKeyboardSyspath, kInhibited));
  EXPECT_EQ(kEnabled, GetSysattr(kKeyboardSyspath, kPowerWakeup));
  EXPECT_EQ("0", GetSysattr(kTouchscreenSyspath, kInhibited));
  EXPECT_EQ(kEnabled, GetSysattr(kTouchscreenSyspath, kPowerWakeup));

  // Lid-closed mode should take precedence over tablet mode. (See b/119287727)
  input_device_controller_.SetTabletMode(TabletMode::ON);
  input_device_controller_.SetLidState(LidState::CLOSED);
  EXPECT_EQ("1", GetSysattr(kKeyboardSyspath, kInhibited));
  EXPECT_EQ(kDisabled, GetSysattr(kKeyboardSyspath, kPowerWakeup));
  EXPECT_EQ("1", GetSysattr(kTouchscreenSyspath, kInhibited));
  EXPECT_EQ(kDisabled, GetSysattr(kTouchscreenSyspath, kPowerWakeup));

  // Display-off mode should take precedence over tablet mode.
  input_device_controller_.SetDisplayMode(DisplayMode::PRESENTATION);
  input_device_controller_.SetLidState(LidState::OPEN);
  input_device_controller_.SetTabletMode(TabletMode::ON);
  input_device_controller_.OnBrightnessChange(
      0.0, BacklightBrightnessChange_Cause_USER_REQUEST,
      &backlight_controller_);
  EXPECT_EQ("0", GetSysattr(kKeyboardSyspath, kInhibited));
  EXPECT_EQ(kEnabled, GetSysattr(kKeyboardSyspath, kPowerWakeup));
  EXPECT_EQ("1", GetSysattr(kTouchscreenSyspath, kInhibited));
  EXPECT_EQ(kDisabled, GetSysattr(kTouchscreenSyspath, kPowerWakeup));
}

TEST_F(InputDeviceControllerTest, UsableWithoutWakeup) {
  // Add a keyboard device that should remain usable while in tablet mode (say,
  // because it also produces power button events: http://crbug.com/703691) but
  // that should only wake the device while in laptop mode.
  const char kKeyboardSyspath[] = "/sys/devices/keyboard/0";
  AddDeviceWithTags(kKeyboardSyspath, kTagInhibit, kTagUsableWhenLaptop,
                    kTagUsableWhenTablet, kTagWakeup, kTagWakeupWhenLaptop,
                    nullptr);

  initial_tablet_mode_ = TabletMode::OFF;
  InitInputDeviceController();
  EXPECT_EQ("0", GetSysattr(kKeyboardSyspath, kInhibited));
  EXPECT_EQ(kEnabled, GetSysattr(kKeyboardSyspath, kPowerWakeup));

  input_device_controller_.SetTabletMode(TabletMode::ON);
  EXPECT_EQ("0", GetSysattr(kKeyboardSyspath, kInhibited));
  EXPECT_EQ(kDisabled, GetSysattr(kKeyboardSyspath, kPowerWakeup));

  input_device_controller_.SetTabletMode(TabletMode::OFF);
  EXPECT_EQ("0", GetSysattr(kKeyboardSyspath, kInhibited));
  EXPECT_EQ(kEnabled, GetSysattr(kKeyboardSyspath, kPowerWakeup));
}

TEST_F(InputDeviceControllerTest, InitWithoutBacklightController) {
  // Init with null backlight controller shouldn't crash.
  input_device_controller_.Init(
      nullptr, &udev_, &acpi_wakeup_helper_, &ec_helper_, initial_lid_state_,
      initial_tablet_mode_, initial_display_mode_, &prefs_);
}

}  // namespace power_manager::policy
