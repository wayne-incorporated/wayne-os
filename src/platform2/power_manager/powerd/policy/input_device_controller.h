// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_INPUT_DEVICE_CONTROLLER_H_
#define POWER_MANAGER_POWERD_POLICY_INPUT_DEVICE_CONTROLLER_H_

#include <string>

#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/policy/backlight_controller_observer.h"
#include "power_manager/powerd/system/udev_tagged_device_observer.h"
#include "power_manager/proto_bindings/backlight.pb.h"

namespace power_manager {
class PrefsInterface;

namespace system {
class AcpiWakeupHelperInterface;
class CrosEcHelperInterface;
class TaggedDevice;
class UdevInterface;
}  // namespace system

namespace policy {

// Configures wakeup-capable devices according to the current lid state.
class InputDeviceController : public policy::BacklightControllerObserver,
                              public system::UdevTaggedDeviceObserver {
 public:
  // Powerd tags.
  static const char kTagInhibit[];
  static const char kTagUsableWhenDocked[];
  static const char kTagUsableWhenDisplayOff[];
  static const char kTagUsableWhenLaptop[];
  static const char kTagUsableWhenTablet[];
  static const char kTagWakeup[];
  static const char kTagWakeupWhenDocked[];
  static const char kTagWakeupWhenDisplayOff[];
  static const char kTagWakeupWhenLaptop[];
  static const char kTagWakeupWhenTablet[];
  static const char kTagWakeupOnlyWhenUsable[];
  static const char kTagWakeupDisabled[];

  // Sysfs power/wakeup constants.
  static const char kWakeupEnabled[];
  static const char kWakeupDisabled[];

  static const char kInhibited[];

  // ACPI device names.
  static const char kTPAD[];
  static const char kTSCR[];
  static const char kCRFP[];

  // Describes which mode the system is currently in, depending on e.g. the
  // state of the lid.
  enum class Mode {
    CLOSED = 0,   // Lid closed, no external monitor attached.
    DOCKED,       // Lid closed, external monitor attached.
    DISPLAY_OFF,  // Internal display off, external monitor attached.
    LAPTOP,       // Lid open.
    TABLET,       // Tablet mode, e.g. lid open more than 180 degrees.
  };

  InputDeviceController() = default;
  InputDeviceController(const InputDeviceController&) = delete;
  InputDeviceController& operator=(const InputDeviceController&) = delete;

  ~InputDeviceController() override;

  void Init(policy::BacklightController* backlight_controller,
            system::UdevInterface* udev,
            system::AcpiWakeupHelperInterface* acpi_wakeup_helper,
            system::CrosEcHelperInterface* ec_helper,
            LidState lid_state,
            TabletMode tablet_mode,
            DisplayMode display_mode,
            PrefsInterface* prefs);

  void SetLidState(LidState lid_state);
  void SetTabletMode(TabletMode tablet_mode);
  void SetDisplayMode(DisplayMode display_mode);

  // Implementation of TaggedDeviceObserver.
  void OnTaggedDeviceChanged(const system::TaggedDevice& device) override;
  void OnTaggedDeviceRemoved(const system::TaggedDevice& device) override;

  // Overridden from policy::BacklightControllerObserver:
  void OnBrightnessChange(double brightness_percent,
                          BacklightBrightnessChange_Cause cause,
                          BacklightController* source) override;

 private:
  // Derive the currently applicable mode according to lid state.
  Mode GetMode() const;

  // Enables or disables wakeup from S3 for this device (through power/wakeup).
  void SetWakeupFromS3(const system::TaggedDevice& device, bool enabled);

  // Configures inhibit for |device| according to our policy.
  void ConfigureInhibit(const system::TaggedDevice& device);

  // Configures wakeup for |device| according to our policy.
  void ConfigureWakeup(const system::TaggedDevice& device);

  // Re-configures ACPI wakeup.
  void ConfigureAcpiWakeup();

  // Re-configures EC wakeup.
  void ConfigureEcWakeup();

  // Re-configures all known devices to reflect a policy change.
  void UpdatePolicy();

  system::UdevInterface* udev_ = nullptr;                            // weak
  policy::BacklightController* backlight_controller_ = nullptr;      // weak
  system::AcpiWakeupHelperInterface* acpi_wakeup_helper_ = nullptr;  // weak
  system::CrosEcHelperInterface* ec_helper_ = nullptr;               // weak

  PrefsInterface* prefs_ = nullptr;  // weak

  LidState lid_state_ = LidState::OPEN;
  TabletMode tablet_mode_ = TabletMode::OFF;
  DisplayMode display_mode_ = DisplayMode::NORMAL;
  bool backlight_enabled_ = false;

  // The mode calculated in the most recent invocation of UpdatePolicy().
  Mode mode_ = Mode::LAPTOP;

  bool initialized_ = false;
};

}  // namespace policy
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_POLICY_INPUT_DEVICE_CONTROLLER_H_
