// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SENSOR_SENSITIVE_SENSOR_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SENSOR_SENSITIVE_SENSOR_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <base/values.h>
#include <base/time/tick_clock.h>
#include <iioservice/mojo/sensor.mojom.h>
#include <mojo/public/cpp/bindings/receiver_set.h>

#include "diagnostics/cros_healthd/routines/diag_routine_with_status.h"
#include "diagnostics/cros_healthd/routines/sensor/sensitive_sensor_constants.h"
#include "diagnostics/cros_healthd/routines/sensor/sensor_existence_checker.h"
#include "diagnostics/cros_healthd/system/mojo_service.h"
#include "diagnostics/cros_healthd/system/system_config_interface.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

constexpr base::TimeDelta kSensitiveSensorRoutineTimeout = base::Seconds(20);

// The sensitive sensor routine checks that the device's sensors are working
// correctly by acquiring dynamic sensor sample data without user interaction.
class SensitiveSensorRoutine final
    : public DiagnosticRoutineWithStatus,
      public cros::mojom::SensorDeviceSamplesObserver {
 public:
  explicit SensitiveSensorRoutine(MojoService* const mojo_service,
                                  SystemConfigInterface* const system_config);
  SensitiveSensorRoutine(const SensitiveSensorRoutine&) = delete;
  SensitiveSensorRoutine& operator=(const SensitiveSensorRoutine&) = delete;
  ~SensitiveSensorRoutine() override;

  // DiagnosticRoutine overrides:
  void Start() override;
  void Resume() override;
  void Cancel() override;
  void PopulateStatusUpdate(ash::cros_healthd::mojom::RoutineUpdate* response,
                            bool include_output) override;

 private:
  struct SensorDetail {
    // Sensor types.
    std::vector<cros::mojom::DeviceType> types;
    // Sensor channels.
    std::optional<std::vector<std::string>> channels;
    // First is channel indice, second is the last reading sample. If the
    // channel finishes checking, remove it from this map.
    std::map<int32_t, std::optional<int64_t>> checking_channel_sample;

    // Update the sample for channel at index |indice|.
    void UpdateChannelSample(int32_t indice, int64_t value);

    // Return the detail for output dict.
    base::Value::Dict GetDetailValue(int32_t id);
  };

  // Handle the response of sensor ids and types from the sensor service.
  void HandleGetAllDeviceIdsResponse(
      const base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>&
          ids_types);

  // Handle the response of sensor verification from the config checker.
  void HandleVerificationResponse(
      const base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>&
          ids_types,
      std::map<SensorType, SensorExistenceChecker::Result>
          existence_check_result);

  // Initialize sensor device to read samples.
  void InitSensorDevice(int32_t sensor_id);

  // Handle the response of frequency from the sensor device after setting
  // reading frequency.
  void HandleFrequencyResponse(int32_t sensor_id, double frequency);

  // Handle the response of channels from the sensor device.
  void HandleChannelIdsResponse(int32_t sensor_id,
                                const std::vector<std::string>& channels);

  // Handle the response of failed channel indices from the sensor device after
  // setting channels enabled.
  void HandleSetChannelsEnabledResponse(
      int32_t sensor_id, const std::vector<int32_t>& failed_indices);

  // Stop all sensor devices and complete the routine on timeout.
  void OnTimeoutOccurred();

  // Routine completion function.
  void OnRoutineFinished();

  // Set the routine result and stop other callbacks.
  void SetResultAndStop(
      ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum status,
      std::string status_message);

  // Create routine output for the given sensor type.
  base::Value::Dict ConstructSensorOutput(SensorType sensor);

  // cros::mojom::SensorDeviceSamplesObserver overrides:
  void OnSampleUpdated(const base::flat_map<int32_t, int64_t>& sample) override;
  void OnErrorOccurred(cros::mojom::ObserverErrorType type) override;

  // Unowned. Should outlive this instance.
  MojoService* const mojo_service_;
  // Used to check if any sensor is missing by iioservice by checking static
  // configuration.
  SensorExistenceChecker sensor_checker_;
  // Details of the result from |sensor_checker_|.
  std::map<SensorType, SensorExistenceChecker::Result> existence_check_result_;
  // Details of the passed sensors and failed sensors, stored in |output| of
  // |response| and reported in status updates if requested. Also used to
  // calculate the progress percentage.
  std::map<int32_t, base::Value::Dict> passed_sensors_;
  std::map<int32_t, base::Value::Dict> failed_sensors_;
  // First is unfinished sensor id and second is the sensor detail. Also used to
  // handle timeout and calculate the progress percentage.
  std::map<int32_t, SensorDetail> pending_sensors_;
  // Routine start time, used to calculate the progress percentage.
  base::TimeTicks start_ticks_;
  // Mojo receiver set for binding pipe, which context is sensor id.
  mojo::ReceiverSet<cros::mojom::SensorDeviceSamplesObserver, int32_t>
      observer_receiver_set_;
  // Must be the last class member.
  base::WeakPtrFactory<SensitiveSensorRoutine> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SENSOR_SENSITIVE_SENSOR_H_
