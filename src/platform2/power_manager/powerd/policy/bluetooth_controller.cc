// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/bluetooth_controller.h"

#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/containers/contains.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <featured/feature_library.h>

namespace power_manager::policy {
namespace {

// Check if the path exists at the wakeup path and return the
// path to the power/control path if it does.
base::FilePath GetSysattrPathFromWakeupDevicePath(
    const std::string& sysattr_fragment,
    const base::FilePath& wakeup_device_path,
    const std::string& syspath) {
  base::FilePath control_path = wakeup_device_path.Append(sysattr_fragment);

  if (!base::PathExists(control_path)) {
    return base::FilePath();
  }

  if (!base::PathIsReadable(control_path) ||
      !base::PathIsWritable(control_path)) {
    LOG(ERROR) << "Bluetooth device " << sysattr_fragment
               << " is not accessible to powerd: " << control_path
               << ", syspath=" << syspath;
  }

  return control_path;
}

base::FilePath GetControlPathFromWakeupDevicePath(
    const base::FilePath& wakeup_device_path, const std::string& syspath) {
  return GetSysattrPathFromWakeupDevicePath(
      BluetoothController::kAutosuspendSysattr, wakeup_device_path, syspath);
}

base::FilePath GetDelayPathFromWakeupDevicePath(
    const base::FilePath& wakeup_device_path, const std::string& syspath) {
  return GetSysattrPathFromWakeupDevicePath(
      BluetoothController::kAutosuspendDelaySysattr, wakeup_device_path,
      syspath);
}

bool SetPathValue(const base::FilePath& path, const std::string& contents) {
  bool success = base::WriteFile(path, contents.data(), contents.size());
  LOG(INFO) << "Writing \"" << contents << "\" to " << path << " "
            << (success ? "succeeded" : "failed");
  return success;
}
}  // namespace

const char BluetoothController::kUdevSubsystemBluetooth[] = "bluetooth";
const char BluetoothController::kUdevDevtypeHost[] = "host";
const char BluetoothController::kUdevSubsystemInput[] = "input";

// See https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-devices-power
const char BluetoothController::kAutosuspendSysattr[] = "power/control";
const char BluetoothController::kAutosuspendDelaySysattr[] =
    "power/autosuspend_delay_ms";
const char BluetoothController::kAutosuspendEnabled[] = "auto";
const char BluetoothController::kAutosuspendDisabled[] = "on";

const char BluetoothController::kBluetoothInputRole[] = "cros_bluetooth";

// Long timeout is 2 minutes.
const char BluetoothController::kLongAutosuspendTimeout[] = "120000";
// Default timeout is 2s (Linux standard).
const char BluetoothController::kDefaultAutosuspendTimeout[] = "2000";

// Long autosuspend feature.
const char BluetoothController::kLongAutosuspendFeatureName[] =
    "CrOSLateBootLongBluetoothAutosuspend";
const VariationsFeature kLongAutosuspendFeature{
    BluetoothController::kLongAutosuspendFeatureName,
    FEATURE_DISABLED_BY_DEFAULT};

BluetoothController::BluetoothController() = default;
BluetoothController::~BluetoothController() {
  if (udev_) {
    udev_->RemoveSubsystemObserver(kUdevSubsystemBluetooth, this);
    udev_->RemoveTaggedDeviceObserver(this);
  }
}

void BluetoothController::Init(
    system::UdevInterface* udev,
    feature::PlatformFeaturesInterface* platform_features,
    system::DBusWrapperInterface* dbus_wrapper) {
  DCHECK(udev);
  DCHECK(platform_features);
  DCHECK(dbus_wrapper);

  udev_ = udev;
  platform_features_ = platform_features;

  // Register for udev updates.
  udev_->AddSubsystemObserver(kUdevSubsystemBluetooth, this);
  udev_->AddTaggedDeviceObserver(this);

  // List all initial entries in Bluetooth subsystem.
  bt_hosts_.clear();
  std::vector<system::UdevDeviceInfo> found;
  if (udev_->GetSubsystemDevices(kUdevSubsystemBluetooth, &found)) {
    for (const system::UdevDeviceInfo& dev : found) {
      if (dev.devtype != kUdevDevtypeHost) {
        continue;
      }
      base::FilePath control_path = GetControlPathFromWakeupDevicePath(
          dev.wakeup_device_path, dev.syspath);
      bt_hosts_.emplace(std::make_pair(dev.syspath, control_path));
    }
  }

  // Register for refetch with platform_features. The check for bus is just for
  // tests which don't have a bus assigned.
  if (dbus_wrapper->GetBus() != nullptr) {
    platform_features_->ListenForRefetchNeeded(
        base::BindRepeating(&BluetoothController::RefetchFeatures,
                            weak_ptr_factory_.GetWeakPtr()),
        base::DoNothing());
  }

  // Do the initial fetch.
  RefetchFeatures();
}

void BluetoothController::ApplyAutosuspendQuirk() {
  std::string disable(kAutosuspendDisabled);

  for (const auto& device : bt_hosts_) {
    // If the host device has a power/control sysattr, disable autosuspend
    // before we enter suspend.
    if (device.second != base::FilePath()) {
      std::string current_value;

      // Save previous state.
      if (base::ReadFileToString(device.second, &current_value)) {
        autosuspend_state_before_quirks_[device.second] = current_value;
      }

      if (current_value == disable) {
        return;
      }

      SetPathValue(device.second, disable);
    }
  }
}

void BluetoothController::UnapplyAutosuspendQuirk() {
  // Default the restore action to enabling autosuspend.
  std::string restore(kAutosuspendEnabled);

  for (const auto& device : bt_hosts_) {
    if (device.second != base::FilePath()) {
      std::string current_value;

      // Restore the state of autosuspend before quirks were applied.
      if (base::Contains(autosuspend_state_before_quirks_, device.second)) {
        restore = autosuspend_state_before_quirks_[device.second];
      }

      if (base::ReadFileToString(device.second, &current_value)) {
        if (current_value == restore) {
          return;
        }
      }

      SetPathValue(device.second, restore);
    }
  }

  // Clear previous autosuspend quirks state.
  autosuspend_state_before_quirks_.clear();
}

void BluetoothController::OnTaggedDeviceChanged(
    const system::TaggedDevice& device) {
  // Feature should be enabled for us to handle device changes.
  if (!long_autosuspend_feature_enabled_) {
    return;
  }

  // We only care about devices with the cros_bluetooth tag.
  if (!udev_->HasPowerdRole(device.syspath(), kBluetoothInputRole)) {
    return;
  }

  // Device is already in connected list.
  if (base::Contains(connected_bluetooth_input_devices_, device.syspath())) {
    return;
  }

  base::FilePath delay_path = GetDelayPathFromWakeupDevicePath(
      device.wakeup_device_path(), device.syspath());

  connected_bluetooth_input_devices_.emplace(
      std::make_pair(device.syspath(), delay_path));

  // If this is the first instance of a connected device for this path, set the
  // long autosuspend delay and set the count.
  if (!base::Contains(delay_path_connected_count_, delay_path)) {
    std::string long_autosuspend(kLongAutosuspendTimeout);

    delay_path_connected_count_.emplace(std::make_pair(delay_path, 1));
    SetPathValue(delay_path, long_autosuspend);
  } else {
    delay_path_connected_count_[delay_path]++;
  }
}

void BluetoothController::OnTaggedDeviceRemoved(
    const system::TaggedDevice& device) {
  // Ignore unknown devices.
  if (!base::Contains(connected_bluetooth_input_devices_, device.syspath())) {
    return;
  }

  // Note: We intentionally do not guard against the feature flag. If any
  // devices were added to |connected_bluetooth_input_devices_|, they should be
  // removed to restore the original system state.

  std::string default_autosuspend_delay(kDefaultAutosuspendTimeout);

  // Remove this device from our connected list.
  base::FilePath delay_path =
      connected_bluetooth_input_devices_[device.syspath()];
  connected_bluetooth_input_devices_.erase(device.syspath());

  if (base::Contains(delay_path_connected_count_, delay_path)) {
    delay_path_connected_count_[delay_path]--;

    // If this is the final connection, reset autosuspend delay.
    if (delay_path_connected_count_[delay_path] == 0) {
      SetPathValue(delay_path, default_autosuspend_delay);
      delay_path_connected_count_.erase(delay_path);
    }
  } else {
    // This path shouldn't happen but we should restore to normal delay.
    VLOG(1) << "Known Bluetooth tagged device removed but connected count "
               "didn't exist.";
    SetPathValue(delay_path, default_autosuspend_delay);
  }
}

void BluetoothController::OnUdevEvent(const system::UdevEvent& event) {
  DCHECK_EQ(event.device_info.subsystem, kUdevSubsystemBluetooth);
  if (event.device_info.devtype != kUdevDevtypeHost)
    return;

  base::FilePath control_path;

  // Update the power/control path when bluetooth hosts are added or removed.
  switch (event.action) {
    case system::UdevEvent::Action::ADD:
    case system::UdevEvent::Action::CHANGE:
      control_path = GetControlPathFromWakeupDevicePath(
          event.device_info.wakeup_device_path, event.device_info.syspath);
      bt_hosts_.emplace(
          std::make_pair(event.device_info.syspath, control_path));
      break;

    case system::UdevEvent::Action::REMOVE:
      bt_hosts_.erase(base::FilePath(event.device_info.syspath));
      break;

    default:
      break;
  }
}

void BluetoothController::RefetchFeatures() {
  IsLongAutosuspendFeatureEnabled(
      platform_features_->IsEnabledBlocking(kLongAutosuspendFeature));
}

void BluetoothController::IsLongAutosuspendFeatureEnabled(bool enabled) {
  long_autosuspend_feature_enabled_ = enabled;

  // List all initially tagged devices and update the notification.
  for (const system::TaggedDevice& device : udev_->GetTaggedDevices()) {
    if (long_autosuspend_feature_enabled_) {
      OnTaggedDeviceChanged(device);
    } else {
      OnTaggedDeviceRemoved(device);
    }
  }

  // Log the change in status for this feature.
  LOG(INFO) << "Bluetooth long autosuspend feature is "
            << (long_autosuspend_feature_enabled_ ? "enabled" : "disabled");
}

}  // namespace power_manager::policy
