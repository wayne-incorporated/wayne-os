// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_DELEGATE_FILE_H_
#define POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_DELEGATE_FILE_H_

#include <list>
#include <map>
#include <optional>
#include <string>

#include <base/compiler_specific.h>
#include <base/files/file_path.h>
#include <base/timer/timer.h>

#include "power_manager/powerd/system/ambient_light_sensor_delegate.h"
#include "power_manager/powerd/system/async_file_reader.h"

namespace power_manager::system {

class AmbientLightSensorDelegateFile : public AmbientLightSensorDelegate {
 public:
  // Number of failed init attempts before AmbientLightSensorDelegateFile will
  // start logging warnings or stop trying entirely.
  static const int kNumInitAttemptsBeforeLogging;
  static const int kNumInitAttemptsBeforeGivingUp;

  AmbientLightSensorDelegateFile(SensorLocation expected_sensor_location,
                                 bool allow_ambient_eq);
  // Select a specific device in |device_list_path_| to use.
  AmbientLightSensorDelegateFile(const std::string& expected_device,
                                 bool allow_ambient_eq);
  AmbientLightSensorDelegateFile(const AmbientLightSensorDelegateFile&) =
      delete;
  AmbientLightSensorDelegateFile& operator=(
      const AmbientLightSensorDelegateFile&) = delete;
  ~AmbientLightSensorDelegateFile() override = default;

  void set_device_list_path_for_testing(const base::FilePath& path) {
    device_list_path_ = path;
  }
  void set_poll_interval_for_testing(base::TimeDelta interval) {
    poll_interval_ = interval;
  }

  // Starts polling. If |read_immediately| is true, ReadAls() will also
  // immediately be called synchronously. This is separate from c'tor so that
  // tests can call set_*_for_testing() first.
  void Init(bool read_immediately);

  // If |poll_timer_| is running, calls ReadAls() and returns true. Otherwise,
  // returns false.
  bool TriggerPollTimerForTesting();

  // AmbientLightSensorDelegate implementation:
  bool IsColorSensor() const override;
  base::FilePath GetIlluminancePath() const override;

 private:
  // Starts |poll_timer_|.
  void StartTimer();

  // Handler for a periodic event that reads the ambient light sensor.
  void ReadAls();

  // Asynchronous I/O success and error handlers, respectively.
  void ReadCallback(const std::string& data);
  void ErrorCallback();

  // Asynchronous I/O handlers for color ALS and other utility methods used to
  // put everything together.
  void ReadColorChannelCallback(const ColorChannelInfo* channel,
                                const std::string& data);
  void ErrorColorChannelCallback(const ColorChannelInfo* channel);
  void CollectChannelReadings();

  // Attempts to initialize for a specific device path.
  bool CheckPath(const base::FilePath& check_path);

  // Initializes |als_file_| and optionally color ALS support if it exists.
  // Returns true if at least lux information is available for use.
  bool InitAlsFile();

  // Initializes |color_als_files_|.
  void InitColorAlsFiles(const base::FilePath& device_dir);

  // Path containing backlight devices.  Typically under /sys, but can be
  // overridden by tests.
  base::FilePath device_list_path_;

  // If this isn't the empty string, only attempt to open this specific device.
  const std::string device_;

  // Runs ReadAls().
  base::RepeatingTimer poll_timer_;

  // Time between polls of the sensor file.
  base::TimeDelta poll_interval_;

  // Boolean to indicate if color support should be enabled on this ambient
  // light sensor. Color support should only be enabled if sensor is properly
  // calibrated. Only search for color support if true.
  bool enable_color_support_;

  // Number of attempts to find and open the lux file made so far.
  int num_init_attempts_ = 0;

  // This is the ambient light sensor asynchronous file I/O object.
  AsyncFileReader als_file_;

  // Async file I/O objects for color ALS channels if it is supported.
  // If this map is empty, then there is no color support.
  std::map<const ColorChannelInfo*, AsyncFileReader> color_als_files_;

  // Lux value read by the |als_file_| reader. We need to gather data from all
  // four channels before notifying observers.
  std::optional<int> clear_reading_;
  // Values read by the |color_als_files_| readers. We need to gather data
  // from all four channels before computing a color temperature and notifying
  // observers.
  std::map<const ColorChannelInfo*, int> color_readings_;

  // Location on the device (e.g. lid, base) where this sensor reports itself
  // to be. If set to unknown, powerd looks for a sensor at any location.
  SensorLocation expected_sensor_location_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_DELEGATE_FILE_H_
