// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_EVENT_DEVICE_H_
#define POWER_MANAGER_POWERD_SYSTEM_EVENT_DEVICE_H_

#include "power_manager/powerd/system/event_device_interface.h"

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <base/functional/callback.h>

namespace power_manager::system {

// Real implementation of EventDeviceInterface.
class EventDevice : public EventDeviceInterface {
 public:
  EventDevice(int fd, const base::FilePath& path);
  EventDevice(const EventDevice&) = delete;
  EventDevice& operator=(const EventDevice&) = delete;

  ~EventDevice() override;

  // Implementation of EventDeviceInterface.
  std::string GetDebugName() override;
  std::string GetName() override;
  std::string GetPhysPath() override;
  bool IsCrosFp() override;
  bool IsLidSwitch() override;
  bool IsTabletModeSwitch() override;
  bool IsPowerButton() override;
  bool HoverSupported() override;
  bool HasLeftButton() override;
  LidState GetInitialLidState() override;
  TabletMode GetInitialTabletMode() override;
  ReadResult ReadEvents(std::vector<input_event>* events_out) override;
  void WatchForEvents(const base::RepeatingClosure& new_events_cb) override;

 private:
  // Checks whether bit index |bit| is set in the bitmask returned by
  // EVIOCGBIT(|event_type|).
  bool HasEventBit(int event_type, int bit);

  // Fetches the state of a single switch by using EVIOCGSW. |bit| is one of the
  // SW_* constants.
  bool GetSwitchBit(int bit);

  int fd_;
  base::FilePath path_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> fd_watcher_;
};

class EventDeviceFactory : public EventDeviceFactoryInterface {
 public:
  EventDeviceFactory() = default;
  EventDeviceFactory(const EventDeviceFactory&) = delete;
  EventDeviceFactory& operator=(const EventDeviceFactory&) = delete;

  ~EventDeviceFactory() override = default;

  // Implementation of EventDeviceFactoryInterface.
  std::shared_ptr<EventDeviceInterface> Open(
      const base::FilePath& path) override;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_EVENT_DEVICE_H_
