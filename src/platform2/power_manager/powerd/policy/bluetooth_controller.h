// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_BLUETOOTH_CONTROLLER_H_
#define POWER_MANAGER_POWERD_POLICY_BLUETOOTH_CONTROLLER_H_

#include <string>

#include <base/containers/flat_map.h>
#include <base/files/file_path.h>
#include <base/memory/weak_ptr.h>
#include <featured/feature_library.h>

#include "power_manager/powerd/system/dbus_wrapper.h"
#include "power_manager/powerd/system/udev.h"
#include "power_manager/powerd/system/udev_subsystem_observer.h"
#include "power_manager/powerd/system/udev_tagged_device_observer.h"

namespace power_manager::policy {

// BluetoothController initiates power-related changes to the Bluetooth chipset.
class BluetoothController : public system::UdevSubsystemObserver,
                            public system::UdevTaggedDeviceObserver {
 public:
  // Bluetooth subsystem and host devtype for udev events.
  static const char kUdevSubsystemBluetooth[];
  static const char kUdevDevtypeHost[];
  // Input subsystem devtype for udev events.
  static const char kUdevSubsystemInput[];

  // Runtime suspend control and enabled/disabled constants.
  static const char kAutosuspendSysattr[];
  static const char kAutosuspendDelaySysattr[];
  static const char kAutosuspendEnabled[];
  static const char kAutosuspendDisabled[];

  // Constants for POWERD_ROLE tag for Bluetooth.
  static const char kBluetoothInputRole[];

  // Constants for autosuspend timeout
  static const char kLongAutosuspendTimeout[];
  static const char kDefaultAutosuspendTimeout[];

  // Feature for enabling long autosuspend duration when HID devices are
  // connected (used for finch rollout).
  static const char kLongAutosuspendFeatureName[];

  BluetoothController();
  BluetoothController(const BluetoothController&) = delete;
  BluetoothController& operator=(const BluetoothController&) = delete;

  ~BluetoothController() override;

  void Init(system::UdevInterface* udev,
            feature::PlatformFeaturesInterface* platform_features,
            system::DBusWrapperInterface* dbus_wrapper);

  // Bluetooth devices currently have a quirk where suspending while
  // autosuspended can cause events to increment the wake count while
  // suspending. To get around this, we disable autosuspend before suspending
  // and re-enable it after suspend.
  void ApplyAutosuspendQuirk();

  // Unapply the autosuspend quirk.
  void UnapplyAutosuspendQuirk();

  // system::UdevSubsystemObserver
  void OnUdevEvent(const system::UdevEvent& event) override;

  // system::UdevTaggedDeviceObserver
  void OnTaggedDeviceChanged(const system::TaggedDevice& device) override;
  void OnTaggedDeviceRemoved(const system::TaggedDevice& device) override;

 private:
  // Called when we need to refetch features.
  void RefetchFeatures();

  // Apply result of feature query.
  void IsLongAutosuspendFeatureEnabled(bool enabled);

  system::UdevInterface* udev_ = nullptr;  // Not owned.

  feature::PlatformFeaturesInterface* platform_features_;  // Not owned

  // Is the feature to enable long autosuspend when hid devices connect enabled?
  bool long_autosuspend_feature_enabled_ = false;

  // Map of known Bluetooth devices and their power/control path.
  base::flat_map<base::FilePath, base::FilePath> bt_hosts_;

  // Map of saved autosuspend states before applying quirks for suspend.
  base::flat_map<base::FilePath, std::string> autosuspend_state_before_quirks_;

  // Map of currently connected Bluetooth input devices and its mapped
  // autosuspend delay path.
  base::flat_map<std::string, base::FilePath>
      connected_bluetooth_input_devices_;

  // Map of autosuspend delay path and current connected device count.
  base::flat_map<base::FilePath, int> delay_path_connected_count_;

  base::WeakPtrFactory<BluetoothController> weak_ptr_factory_{this};
};

}  // namespace power_manager::policy

#endif  // POWER_MANAGER_POWERD_POLICY_BLUETOOTH_CONTROLLER_H_
