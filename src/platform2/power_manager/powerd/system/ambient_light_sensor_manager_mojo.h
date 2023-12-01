// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_MANAGER_MOJO_H_
#define POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_MANAGER_MOJO_H_

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/sequence_checker.h>
#include <iioservice/mojo/cros_sensor_service.mojom.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "power_manager/powerd/system/ambient_light_sensor.h"
#include "power_manager/powerd/system/ambient_light_sensor_manager_interface.h"
#include "power_manager/powerd/system/sensor_service_handler.h"
#include "power_manager/powerd/system/sensor_service_handler_observer.h"

namespace power_manager {

class PrefsInterface;

namespace system {

// AmbientLightSensorManagerMojo should be used on the same thread.
class AmbientLightSensorManagerMojo : public AmbientLightSensorManagerInterface,
                                      public SensorServiceHandlerObserver {
 public:
  AmbientLightSensorManagerMojo(PrefsInterface* prefs,
                                SensorServiceHandler* sensor_service_handler);
  AmbientLightSensorManagerMojo(const AmbientLightSensorManagerMojo&) = delete;
  AmbientLightSensorManagerMojo& operator=(
      const AmbientLightSensorManagerMojo&) = delete;
  ~AmbientLightSensorManagerMojo() override;

  // AmbientLightSensorManagerInterface overrides:
  AmbientLightSensorInterface* GetSensorForInternalBacklight() override;
  AmbientLightSensorInterface* GetSensorForKeyboardBacklight() override;
  bool HasColorSensor() override;

  // SensorServiceHandlerObserver overrides:
  void OnNewDeviceAdded(
      int32_t iio_device_id,
      const std::vector<cros::mojom::DeviceType>& types) override;
  void SensorServiceConnected() override;
  void SensorServiceDisconnected() override;

  void SetClosureForTesting(base::RepeatingClosure closure_for_testing_lid,
                            base::RepeatingClosure closure_for_testing_base) {
    lid_sensor_.closure_for_testing = closure_for_testing_lid;
    base_sensor_.closure_for_testing = closure_for_testing_base;
  }

 private:
  struct Sensor {
    std::optional<int> iio_device_id;
    system::AmbientLightSensor* sensor = nullptr;

    base::RepeatingClosure closure_for_testing;
  };

  struct LightData {
    // Something is wrong of the attributes, or this light sensor is not needed.
    bool ignored = false;

    std::optional<std::string> name;
    std::optional<SensorLocation> location;

    // Temporarily stores the accelerometer mojo::Remote, waiting for its
    // attribute information. It'll be passed to AmbientLightSensorDelegateMojo
    // as an argument after all information is collected.
    mojo::Remote<cros::mojom::SensorDevice> remote;
  };

  void ResetSensorService();

  // Called when an in-use device is unplugged, and we need to search for other
  // devices to use.
  void ResetStates();
  void QueryDevices();

  void OnSensorDeviceDisconnect(int32_t id,
                                uint32_t custom_reason_code,
                                const std::string& description);

  void GetNameCallback(int32_t id,
                       const std::vector<std::optional<std::string>>& values);
  void GetNameAndLocationCallback(
      int32_t id, const std::vector<std::optional<std::string>>& values);
  void SetSensorDeviceAtLocation(int32_t id, SensorLocation location);

  void AllDevicesFound();

  void SetSensorDeviceMojo(Sensor* sensor, bool allow_ambient_eq);

  int64_t num_sensors_ = 0;
  bool allow_ambient_eq_ = false;

  // First is the device id, second is it's data and mojo remote. Only used if
  // |num_sensors_| is greater or equals to 2.
  std::map<int32_t, LightData> lights_;

  std::vector<std::unique_ptr<AmbientLightSensor>> sensors_;

  // iio_device_ids and unowned pointers into the relevant entries of
  // |sensors_|.
  Sensor lid_sensor_;
  Sensor base_sensor_;

  SEQUENCE_CHECKER(sequence_checker_);
};

}  // namespace system
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_MANAGER_MOJO_H_
