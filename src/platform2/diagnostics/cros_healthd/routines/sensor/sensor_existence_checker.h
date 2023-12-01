// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SENSOR_SENSOR_EXISTENCE_CHECKER_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SENSOR_SENSOR_EXISTENCE_CHECKER_H_

#include <map>
#include <set>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <iioservice/mojo/sensor.mojom.h>

#include "diagnostics/cros_healthd/system/mojo_service.h"
#include "diagnostics/cros_healthd/system/system_config_interface.h"

namespace diagnostics {

// Check if the sensor info from iioservice is consistent with static config.
class SensorExistenceChecker {
 public:
  explicit SensorExistenceChecker(MojoService* const mojo_service,
                                  SystemConfigInterface* const system_config);
  SensorExistenceChecker(const SensorExistenceChecker&) = delete;
  SensorExistenceChecker& operator=(const SensorExistenceChecker&) = delete;
  ~SensorExistenceChecker();

  struct Result {
    enum State {
      // The sensors from iioservice match the static config.
      kPassed,
      // The static config is null.
      kSkipped,
      // The static config is true, but we can't find the sensor.
      kMissing,
      // The static config is false, but we get the sensor unexpectedly.
      kUnexpected
    };
    State state;
    // The IDs of the sensor that belongs to the corresponding sensor type.
    std::vector<int32_t> sensor_ids;
  };

  void VerifySensorInfo(
      const base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>&
          ids_types,
      base::OnceCallback<void(std::map<SensorType, Result>)> on_finish);

 private:
  // Handle the response of sensor attributes from the sensor device.
  void HandleSensorLocationResponse(
      int32_t sensor_id,
      const std::vector<cros::mojom::DeviceType>& sensor_types,
      const std::vector<std::optional<std::string>>& attributes);

  // Existence check completion function.
  void CheckSystemConfig(
      base::OnceCallback<void(std::map<SensorType, Result>)> on_finish,
      bool all_callbacks_called);

  // Unowned. Should outlive this instance.
  MojoService* const mojo_service_;
  SystemConfigInterface* const system_config_;

  // Used to check if the target sensor is present. The second is sensor ids of
  // the type.
  std::map<SensorType, std::vector<int32_t>> iio_sensor_ids_{};

  // Must be the last class member.
  base::WeakPtrFactory<SensorExistenceChecker> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SENSOR_SENSOR_EXISTENCE_CHECKER_H_
