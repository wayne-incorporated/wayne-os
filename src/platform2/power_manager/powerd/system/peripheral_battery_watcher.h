// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_PERIPHERAL_BATTERY_WATCHER_H_
#define POWER_MANAGER_POWERD_SYSTEM_PERIPHERAL_BATTERY_WATCHER_H_

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/observer_list.h>
#include <base/time/time.h>
#include <base/timer/timer.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>

#include "power_manager/powerd/system/async_file_reader.h"
#include "power_manager/powerd/system/bluez_battery_provider.h"
#include "power_manager/powerd/system/udev_subsystem_observer.h"

namespace power_manager::system {

class DBusWrapperInterface;

class PeripheralBatteryWatcher : public UdevSubsystemObserver {
 public:
  // sysfs file containing a battery's scope.
  static const char kScopeFile[];
  // kScopeFile value used for peripheral batteries.
  static const char kScopeValueDevice[];

  // sysfs file containing a battery's status.
  static const char kStatusFile[];
  // sysfs file containing a uevent info.
  static const char kPowersUeventFile[];
  // kStatusFile value used to report an unknown status.
  static const char kStatusValueUnknown[];
  // kStatusFile value used to report battery is full.
  static const char kStatusValueFull[];
  // kStatusFile value used to report battery is charging.
  static const char kStatusValueCharging[];
  // kStatusFile value used to report battery is discharging.
  static const char kStatusValueDischarging[];
  // kStatusFile value used to report battery is not charging.
  static const char kStatusValueNotcharging[];

  // sysfs file containing a battery's health.
  static const char kHealthFile[];
  // kHealthFile value used to report an unknown health.
  static const char kHealthValueUnknown[];
  // kHealthFile value used to report good health.
  static const char kHealthValueGood[];

  // sysfs file containing a battery's model name.
  static const char kModelNameFile[];
  // sysfs file containing a battery's capacity.
  static const char kCapacityFile[];
  // sysfs file containing a battery's serial number.
  static const char kSerialNumberFile[];
  // udev subsystem to listen to for peripheral battery events.
  static const char kUdevSubsystem[];

  PeripheralBatteryWatcher();
  PeripheralBatteryWatcher(const PeripheralBatteryWatcher&) = delete;
  PeripheralBatteryWatcher& operator=(const PeripheralBatteryWatcher&) = delete;

  ~PeripheralBatteryWatcher() override;

  void set_battery_path_for_testing(const base::FilePath& path) {
    peripheral_battery_path_ = path;
  }

  // Starts polling.
  void Init(DBusWrapperInterface* dbus_wrapper, UdevInterface* udev);

  // UdevSubsystemObserver implementation:
  void OnUdevEvent(const UdevEvent& event) override;

 private:
  friend class PeripheralBatteryWatcherTest;

  // Reads battery status of a single peripheral device and send out a signal.
  void ReadBatteryStatus(const base::FilePath& path, bool active_update);

  // Handler for a periodic event that reads the peripheral batteries'
  // level.
  void ReadBatteryStatusesTimer();

  // Perform operation to read and send status of all statuses.
  void ReadBatteryStatuses();

  // Detects if |device_path| in /sys/class/power_supply is a peripheral device.
  bool IsPeripheralDevice(const base::FilePath& device_path) const;

  // Detects if |device_path| in /sys/class/power_supply is a charger of
  // peripheral devices.
  bool IsPeripheralChargerDevice(const base::FilePath& device_path) const;

  // Retrieves state of charge from status and health entries in
  // /sys/class/power_supply
  int ReadChargeStatus(const base::FilePath& path) const;

  // Retrieves battery serial_number entry in /sys/class/power_supply
  std::string ReadSerialNumber(const base::FilePath& path) const;

  // Fills |battery_list| with paths containing information about
  // peripheral batteries.
  void GetBatteryList(std::vector<base::FilePath>* battery_list);

  // Sends the battery status through D-Bus using powerd's
  // PeripheralBatteryStatus signal, including current charge level and
  // charge status. active_update is true if this was an event
  // driven update, not just polled.
  // Note: Battery status of Bluetooth devices is not advertised using powerd's
  // PeripheralBatteryStatus signal, but communicated to BlueZ using BlueZ's
  // Battery provider API.
  void SendBatteryStatus(const base::FilePath& path,
                         const std::string& model_name,
                         int level,
                         int charge_status,
                         const std::string& serial_number,
                         bool active_update);

  // Asynchronous I/O success and error handlers, respectively.
  void ReadCallback(const base::FilePath& path,
                    const std::string& model_name,
                    int status,
                    const std::string& serial_number,
                    bool active_update,
                    base::TimeTicks start_time,
                    const std::string& data);
  void ErrorCallback(const base::FilePath& path,
                     const std::string& model_name,
                     base::TimeTicks start_time);

  // Useful to pass mock BluezBatteryProvider in tests.
  void SetBluezBatteryProviderForTest(
      std::unique_ptr<BluezBatteryProvider> bluez_battery_provider) {
    bluez_battery_provider_ = std::move(bluez_battery_provider);
  }

  // Handles D-Bus method calls.
  void OnRefreshAllPeripheralBatteryMethodCall(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);

  DBusWrapperInterface* dbus_wrapper_ = nullptr;  // weak

  UdevInterface* udev_ = nullptr;  // non-owned

  // Path containing battery info for peripheral devices.
  base::FilePath peripheral_battery_path_;

  // Calls ReadBatteryStatuses().
  base::RepeatingTimer poll_timer_;

  // AsyncFileReaders for different peripheral batteries.
  std::map<base::FilePath, std::unique_ptr<AsyncFileReader>> battery_readers_;

  std::unique_ptr<BluezBatteryProvider> bluez_battery_provider_;

  base::WeakPtrFactory<PeripheralBatteryWatcher> weak_ptr_factory_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_PERIPHERAL_BATTERY_WATCHER_H_
