// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_WAKEUP_SOURCE_IDENTIFIER_H_
#define POWER_MANAGER_POWERD_SYSTEM_WAKEUP_SOURCE_IDENTIFIER_H_

#include <map>
#include <memory>
#include <set>
#include <string>

#include <base/files/file_path.h>

#include "power_manager/powerd/system/udev_subsystem_observer.h"
#include "power_manager/powerd/system/wakeup_source_identifier_interface.h"

namespace power_manager::system {

struct UdevEvent;
class UdevInterface;
class WakeupDeviceInterface;

class WakeupSourceIdentifier : public WakeupSourceIdentifierInterface,
                               public UdevSubsystemObserver {
 public:
  explicit WakeupSourceIdentifier(UdevInterface* udev);
  WakeupSourceIdentifier(const WakeupSourceIdentifier&) = delete;
  WakeupSourceIdentifier& operator=(const WakeupSourceIdentifier&) = delete;

  ~WakeupSourceIdentifier() override;

  // WakeupSourceIdentifierInterface implementation.
  void PrepareForSuspendRequest() override;
  void HandleResume() override;
  bool InputDeviceCausedLastWake() const override;

  // UdevSubsystemObserver implementation.
  void OnUdevEvent(const UdevEvent& event) override;

 private:
  // Handles an input being added to or removed from the system.
  void HandleAddedInput(const std::string& input_name,
                        const base::FilePath& wakeup_device_path);
  void HandleRemovedInput(const std::string& input_name);
  UdevInterface* udev_ = nullptr;  // non-owned

  // Keyed by the device sys path. Value is set of input devices
  // names that have this wakeup path.
  using WakeupDeviceMap = std::map<base::FilePath, std::set<std::string>>;
  WakeupDeviceMap wakeup_devices_;

  // Keyed by the device sys path.
  using MonitoredPathsMap =
      std::map<base::FilePath, std::unique_ptr<WakeupDeviceInterface>>;
  MonitoredPathsMap monitored_paths_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_WAKEUP_SOURCE_IDENTIFIER_H_
