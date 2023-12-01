// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_PLUGGABLE_INTERNAL_BACKLIGHT_H_
#define POWER_MANAGER_POWERD_SYSTEM_PLUGGABLE_INTERNAL_BACKLIGHT_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/observer_list.h>

#include "power_manager/powerd/system/backlight_interface.h"
#include "power_manager/powerd/system/udev_subsystem_observer.h"

namespace power_manager::system {

class BacklightObserver;
class InternalBacklight;
struct UdevEvent;
class UdevInterface;

// This class wraps the InternalBacklight class, refreshing it in response to
// udev events about the backlight being added or removed.
class PluggableInternalBacklight : public BacklightInterface,
                                   public UdevSubsystemObserver {
 public:
  PluggableInternalBacklight() = default;
  PluggableInternalBacklight(const PluggableInternalBacklight&) = delete;
  PluggableInternalBacklight& operator=(const PluggableInternalBacklight&) =
      delete;

  ~PluggableInternalBacklight() override;

  // Ownership of |udev| remains with the caller.
  void Init(UdevInterface* udev,
            const std::string& udev_subsystem,
            const base::FilePath& base_path,
            const std::string& pattern);

  // BacklightInterface:
  void AddObserver(BacklightObserver* observer) override;
  void RemoveObserver(BacklightObserver* observer) override;
  bool DeviceExists() const override;
  int64_t GetMaxBrightnessLevel() override;
  int64_t GetCurrentBrightnessLevel() override;
  bool SetBrightnessLevel(int64_t level, base::TimeDelta interval) override;
  BrightnessScale GetBrightnessScale() override;
  bool TransitionInProgress() const override;

  // UdevSubsystemObserver:
  void OnUdevEvent(const UdevEvent& event) override;

 private:
  // Recreates |device_|, setting it to null if the device wasn't found.
  void UpdateDevice();

  base::ObserverList<BacklightObserver> observers_;

  UdevInterface* udev_ = nullptr;  // Not owned.

  // udev subsystem used to observe |udev_|.
  std::string udev_subsystem_;

  // Information used to find the backlight device. See the InternalBacklight
  // class for details.
  base::FilePath base_path_;
  std::string pattern_;

  // The underlying backlight device, or null when the device isn't present.
  std::unique_ptr<InternalBacklight> device_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_PLUGGABLE_INTERNAL_BACKLIGHT_H_
