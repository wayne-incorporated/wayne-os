// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_THERMAL_THERMAL_DEVICE_H_
#define POWER_MANAGER_POWERD_SYSTEM_THERMAL_THERMAL_DEVICE_H_

#include <string>

#include <base/files/file_path.h>
#include <base/observer_list.h>
#include <base/timer/timer.h>
#include <base/time/time.h>

#include "power_manager/powerd/system/async_file_reader.h"
#include "power_manager/powerd/system/thermal/device_thermal_state.h"
#include "power_manager/powerd/system/thermal/thermal_device_observer.h"

namespace power_manager::system {

enum class ThermalDeviceType {
  kUnknown = 0,
  kProcessorCooling,
  kFanCooling,
  kChargerCooling,
  kOtherCooling
};

class ThermalDeviceInterface {
 public:
  ThermalDeviceInterface() = default;
  ThermalDeviceInterface(const ThermalDeviceInterface&) = delete;
  ThermalDeviceInterface& operator=(const ThermalDeviceInterface&) = delete;

  virtual ~ThermalDeviceInterface() = default;

  // Adds or removes observers for thermal state change.
  virtual void AddObserver(ThermalDeviceObserver* observer) = 0;
  virtual void RemoveObserver(ThermalDeviceObserver* observer) = 0;

  // Returns device thermal state of the thermal device being monitored.
  virtual DeviceThermalState GetThermalState() const = 0;

  // Return type of thermal device.
  virtual ThermalDeviceType GetType() const = 0;
};

class ThermalDevice : public ThermalDeviceInterface {
 public:
  ThermalDevice();
  explicit ThermalDevice(base::FilePath device_path);
  ThermalDevice(const ThermalDevice&) = delete;
  ThermalDevice& operator=(const ThermalDevice&) = delete;

  ~ThermalDevice() override = default;

  void set_poll_interval_for_testing(base::TimeDelta interval) {
    poll_interval_ = interval;
  }

  base::FilePath get_device_path_for_testing() { return device_path_; }

  // ThermalDeviceInterface implementation:
  void AddObserver(ThermalDeviceObserver* observer) override;
  void RemoveObserver(ThermalDeviceObserver* observer) override;
  DeviceThermalState GetThermalState() const override;
  ThermalDeviceType GetType() const override;

  // Starts polling. If |read_immediately| is true, ReadDeviceState() will also
  // immediately be called synchronously. This is separate from c'tor so that
  // tests can call set_*_for_testing() first.
  void Init(bool read_immediately);

  // Reads data from |device_path_| to init |polling_file_|.
  virtual bool InitSysfsFile() = 0;

 protected:
  // Convert |sysfs_data| to |DeviceThermalState|.
  virtual DeviceThermalState CalculateThermalState(int sysfs_data) = 0;

  // Directory containing thermal device.
  // Example: /sys/class/thermal/cooling_device0
  base::FilePath device_path_;

  // Path of |polling_file_|.
  // Example: /sys/class/thermal/cooling_device0/cur_state
  base::FilePath polling_path_;

  // File for polling current thermal state.
  AsyncFileReader polling_file_;

  // Number of attempts to find and open the sysfs file made so far.
  int num_init_attempts_;

  // Number of read errors sysfs file so far.
  int num_read_errors_;

  // Type of thermal device.
  ThermalDeviceType type_;

 private:
  // Starts |poll_timer_|.
  void StartTimer();

  // Handler for a periodic event that reads the thermal device state.
  void ReadDeviceState();

  // Asynchronous I/O success and error handlers, respectively.
  void ReadCallback(const std::string& data);
  void ErrorCallback();

  // Updates |current_state_| and calls observer when needed.
  void UpdateThermalState(DeviceThermalState new_state);

  // Runs ReadDeviceState().
  base::RepeatingTimer poll_timer_;

  // Time between polls of the sensor file, in milliseconds.
  base::TimeDelta poll_interval_;

  // List of observers that are currently interested in updates from this.
  base::ObserverList<ThermalDeviceObserver> observers_;

  // Cached value of current thermal state.
  DeviceThermalState current_state_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_THERMAL_THERMAL_DEVICE_H_
