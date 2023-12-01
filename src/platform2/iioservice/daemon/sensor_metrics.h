// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_DAEMON_SENSOR_METRICS_H_
#define IIOSERVICE_DAEMON_SENSOR_METRICS_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/time/time.h>
#include <base/timer/timer.h>
#include <metrics/metrics_library.h>

#include "iioservice/include/export.h"
#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

class IIOSERVICE_EXPORT SensorMetrics {
 public:
  enum class Location {
    kBase = 0,
    kLid = 1,
    kCamera = 2,
    kOthers = 3,
    kMax = 4,
  };

  // Creates the global SensorMetrics instance.
  static void Initialize();

  // Destroys the global SensorMetrics instance if it exists.
  static void Shutdown();

  // Returns a pointer to the global SensorMetrics instance.
  // Initialize(ForTesting)() should already have been called.
  static SensorMetrics* GetInstance();

  ~SensorMetrics();

  void SetConfigForDevice(int iio_device_id,
                          const std::vector<cros::mojom::DeviceType>& types,
                          const std::string& location);

  // Records SensorUsage(Highspeed) of an IIO device in iioservice.
  void SendSensorUsage(int iio_device_id, double frequency);

  // Records SensorObserver(Open) in iioservice.
  void SendSensorObserverOpened();
  void SendSensorObserverClosed();

  // Records SensorClientConcurrent in iioservice.
  void SendSensorClientConnected();
  void SendSensorClientDisconnected();

 protected:
  static void SetInstance(SensorMetrics* sensor_metrics);

  explicit SensorMetrics(std::unique_ptr<MetricsLibraryInterface> metrics_lib);

 private:
  struct DeviceConfig {
    std::vector<cros::mojom::DeviceType> types;
    Location location;

    double frequency = 0.0;

    // Maximum frequency used in the last hour.
    double max_frequency = 0.0;
  };

  SensorMetrics::Location FilterLocationString(std::string location);

  void SummarizeTime();

  std::unique_ptr<MetricsLibraryInterface> metrics_lib_;
  base::RepeatingTimer summarize_timer_;

  // First is the iio_device_id, second is the device's configs.
  std::map<int, DeviceConfig> device_configs_;

  int32_t enable_sensor_observer_counter_ = 0;
  int32_t sensor_observer_counter_ = 0;
  int32_t max_sensor_observer_counter_ = 0;

  int32_t sensor_client_counter_ = 0;
  int32_t max_sensor_client_counter_ = 0;
};

}  // namespace iioservice

#endif  // IIOSERVICE_DAEMON_SENSOR_METRICS_H_
