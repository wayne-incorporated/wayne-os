// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/wakeup_source_identifier.h"

#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/system/udev.h"
#include "power_manager/powerd/system/wakeup_device.h"

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>

namespace power_manager::system {

WakeupSourceIdentifier::WakeupSourceIdentifier(UdevInterface* udev) {
  DCHECK(udev);
  udev_ = udev;
  udev_->AddSubsystemObserver(kInputUdevSubsystem, this);

  std::vector<UdevDeviceInfo> input_device_list;
  if (udev_->GetSubsystemDevices(kInputUdevSubsystem, &input_device_list)) {
    for (const auto& input_device : input_device_list)
      HandleAddedInput(input_device.sysname, input_device.wakeup_device_path);
  } else {
    LOG(ERROR) << "Cannot monitor event counts of input devices. Dark resume "
                  "might not work properly";
  }

  std::vector<UdevDeviceInfo> power_supply_device_list;
  if (udev_->GetSubsystemDevices("power_supply", &power_supply_device_list)) {
    for (const auto& device : power_supply_device_list) {
      auto dirname = device.wakeup_device_path.DirName().value();
      // Filter out other power supplies (e.g. battery) for now.
      if (dirname.find("cros-ec-pchg") != std::string::npos)
        HandleAddedInput(device.sysname, device.wakeup_device_path);
    }
  }
}

WakeupSourceIdentifier::~WakeupSourceIdentifier() {
  udev_->RemoveSubsystemObserver(kInputUdevSubsystem, this);
}

void WakeupSourceIdentifier::PrepareForSuspendRequest() {
  for (const auto& mp : monitored_paths_)
    mp.second->PrepareForSuspend();
}

void WakeupSourceIdentifier::HandleResume() {
  for (const auto& mp : monitored_paths_)
    mp.second->HandleResume();
}

bool WakeupSourceIdentifier::InputDeviceCausedLastWake() const {
  for (const auto& mp : monitored_paths_) {
    if (mp.second->CausedLastWake())
      return true;
  }
  return false;
}

void WakeupSourceIdentifier::OnUdevEvent(const UdevEvent& event) {
  DCHECK_EQ(event.device_info.subsystem, kInputUdevSubsystem);

  if (event.action == UdevEvent::Action::ADD) {
    HandleAddedInput(event.device_info.sysname,
                     event.device_info.wakeup_device_path);
  } else if (event.action == UdevEvent::Action::REMOVE) {
    // wakeup_device_path is not populated in the |event| during
    // UdevEvent::Action::REMOVE event. Thus this code only depends on
    // sysname while processing UdevEvent::Action::REMOVE.
    HandleRemovedInput(event.device_info.sysname);
  }
}

void WakeupSourceIdentifier::HandleAddedInput(
    const std::string& input_name, const base::FilePath& wakeup_device_path) {
  if (wakeup_device_path.empty()) {
    LOG(INFO) << "Input device " << input_name << " is not wake-capable";
    return;
  }

  bool already_monitoring = wakeup_devices_.count(wakeup_device_path) > 0;

  wakeup_devices_[wakeup_device_path].insert(input_name);

  if (already_monitoring)
    return;

  std::unique_ptr<WakeupDeviceInterface> wakeup_device =
      WakeupDevice::CreateWakeupDevice(wakeup_device_path);

  if (!wakeup_device) {
    LOG(ERROR) << "Failed to create wakeup device for " << input_name;
    return;
  }

  monitored_paths_[wakeup_device_path] = std::move(wakeup_device);
  LOG(INFO) << "Monitoring wakeup path " << wakeup_device_path.value()
            << " for wake events";
}

void WakeupSourceIdentifier::HandleRemovedInput(const std::string& input_name) {
  base::FilePath input_device_wakeup_path;

  for (std::pair<const base::FilePath, std::set<std::string>>& wakeup_device :
       wakeup_devices_) {
    if (wakeup_device.second.count(input_name)) {
      wakeup_device.second.erase(input_name);
      input_device_wakeup_path = wakeup_device.first;
    }
  }

  // We were not monitoring this input for wakeup counts at all.
  if (input_device_wakeup_path.empty())
    return;

  if (!wakeup_devices_[input_device_wakeup_path].empty()) {
    // This wake path is monitored to identify wakes from other inputs too. So
    // nothing to do as of now.
    return;
  }

  wakeup_devices_.erase(input_device_wakeup_path);

  bool erase_successful = monitored_paths_.erase(input_device_wakeup_path);
  DCHECK(erase_successful)
      << "state mismatch between wakeup_devices_ and  monitored_paths_";

  LOG(INFO) << "Stopped monitoring wakeup path "
            << input_device_wakeup_path.value() << " for wake events";
}

}  // namespace power_manager::system
