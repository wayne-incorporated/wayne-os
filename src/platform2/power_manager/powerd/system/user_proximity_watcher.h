// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_USER_PROXIMITY_WATCHER_H_
#define POWER_MANAGER_POWERD_SYSTEM_USER_PROXIMITY_WATCHER_H_

#include <memory>
#include <string>
#include <unordered_map>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/observer_list.h>

#include <cros_config/cros_config.h>

#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/system/udev.h"
#include "power_manager/powerd/system/udev_subsystem_observer.h"
#include "power_manager/powerd/system/user_proximity_watcher_interface.h"

namespace power_manager {

class PrefsInterface;

namespace system {

class UserProximityObserver;
struct UdevEvent;
class UdevInterface;

// Concrete implementation of UserProximityWatcherInterface: detects proximity
// sensors and reports proximity events.
class UserProximityWatcher : public UserProximityWatcherInterface,
                             public UdevSubsystemObserver {
 public:
  // Sensor type for proximity detection.
  enum class SensorType { UNKNOWN, SAR, ACTIVITY };

  // udev subsystem to watch.
  static const char kIioUdevSubsystem[];

  // udev device type.
  static const char kIioUdevDevice[];

  // Mechanism to obtain a file handle suitable for observing IIO events
  using OpenIioEventsFunc = base::RepeatingCallback<int(const base::FilePath&)>;

  void set_open_iio_events_func_for_testing(const OpenIioEventsFunc& f);

  UserProximityWatcher();
  UserProximityWatcher(const UserProximityWatcher&) = delete;
  UserProximityWatcher& operator=(const UserProximityWatcher&) = delete;

  ~UserProximityWatcher() override;

  // Returns true on success.
  bool Init(PrefsInterface* prefs,
            UdevInterface* udev,
            std::unique_ptr<brillo::CrosConfigInterface> config,
            TabletMode tablet_mode);

  // UserProximityWatcherInterface implementation:
  void AddObserver(UserProximityObserver* observer) override;
  void RemoveObserver(UserProximityObserver* observer) override;

  // Called when the tablet mode changes.
  void HandleTabletModeChange(TabletMode mode) override;

  // UdevSubsystemObserver implementation:
  void OnUdevEvent(const UdevEvent& event) override;

  // Watcher implementation:
  void OnFileCanReadWithoutBlocking(int fd);

 private:
  struct SensorInfo {
    SensorType type;
    std::string syspath;
    std::string devlink;
    int event_fd;
    // Bitwise combination of UserProximityObserver::SensorRole values
    uint32_t role;
    std::string channel;
    std::unique_ptr<base::FileDescriptorWatcher::Controller> controller;
  };

  // Returns which subsystems the sensor at |path| should provide proximity
  // data for. The allowed roles are filtered based on whether the preferences
  // allow using proximity sensor as an input for a given subsystem. The
  // return value is a bitwise combination of SensorRole values.
  uint32_t GetUsableSensorRoles(const SensorType type, const std::string& path);

  // Determines whether |dev| represents a proximity sensor connected via
  // the IIO subsystem. If so, |devlink_out| is the path to the file to be used
  // to read proximity events from this device.
  bool IsIioSarSensor(const UdevDeviceInfo& dev, std::string* devlink_out);
  bool IsIioActivitySensor(const UdevDeviceInfo& dev, std::string* devlink_out);

  // Configures the SAR sensor for usage based on values read from cros_config
  bool ConfigureSarSensor(SensorInfo* sensor);

  // Configures the activity sensor to enable it.
  bool ConfigureActivitySensor(const std::string& syspath, uint32_t role);

  // Compensates the sensor so that it works in a new configuration such
  // as tablet mode or notebook mode.
  void CompensateSensor(const SensorInfo& sensor);

  // Enables or disables the sensor.
  bool EnableDisableSensor(const SensorInfo& sensor, bool enable);
  // Disables the sensor
  bool DisableSensor(const SensorInfo& sensor);
  // Enables the sensor
  bool EnableSensor(const SensorInfo& sensor);

  // Opens a file descriptor suitable for listening to proximity events for
  // the sensor at |devlink|, and notifies registered observers that a new
  // valid proximity sensor exists.
  bool OnSensorDetected(const SensorType type,
                        const std::string& syspath,
                        const std::string& devlink);

  // Check new udev device. If the device of |device_info| is a proximity
  // sensor, start listening to proximity events for it.
  void OnNewUdevDevice(const UdevDeviceInfo& device_info);

  OpenIioEventsFunc open_iio_events_func_;

  TabletMode tablet_mode_ = TabletMode::UNSUPPORTED;
  UdevInterface* udev_ = nullptr;  // non-owned
  std::unique_ptr<brillo::CrosConfigInterface> config_;
  base::ObserverList<UserProximityObserver> observers_;

  // Mapping between IIO event file descriptors and sensor details.
  std::unordered_map<int, SensorInfo> sensors_;

  bool use_proximity_for_cellular_ = false;
  bool use_proximity_for_wifi_ = false;
  bool use_activity_proximity_for_cellular_ = false;
  bool use_activity_proximity_for_wifi_ = false;
};

}  // namespace system
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_SYSTEM_USER_PROXIMITY_WATCHER_H_
