// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_DAEMON_SENSOR_DEVICE_FUSION_GRAVITY_H_
#define IIOSERVICE_DAEMON_SENSOR_DEVICE_FUSION_GRAVITY_H_

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <base/task/sequenced_task_runner.h>

#include "iioservice/daemon/sensor_device_fusion.h"
#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

class SensorDeviceFusionGravity final : public SensorDeviceFusion {
 public:
  static constexpr char kName[] = "iioservice-gravity";
  static constexpr double kAccelMinFrequency = 20.0;
  static constexpr double kGyroMinFrequency = 20.0;

  static ScopedSensorDeviceFusion Create(
      int32_t id,
      Location location,
      scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
      base::RepeatingCallback<
          void(int32_t iio_device_id,
               mojo::PendingReceiver<cros::mojom::SensorDevice> request)>
          iio_add_receiver_callback,
      double max_frequency,
      int32_t accel_id,
      int32_t gyro_id);

  ~SensorDeviceFusionGravity();

  // SensorDeviceFusion overrides:
  void GetAttributes(const std::vector<std::string>& attr_names,
                     GetAttributesCallback callback) override;
  void GetChannelsAttributes(const std::vector<int32_t>& iio_chn_indices,
                             const std::string& attr_name,
                             GetChannelsAttributesCallback callback) override;

 protected:
  void UpdateRequestedFrequency(double frequency) override;

 private:
  SensorDeviceFusionGravity(
      int32_t id,
      Location location,
      scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
      base::RepeatingCallback<
          void(int32_t iio_device_id,
               mojo::PendingReceiver<cros::mojom::SensorDevice> request)>
          iio_add_receiver_callback,
      double max_frequency,
      std::vector<std::string> channel_ids,
      int32_t accel_id,
      int32_t gyro_id);

  void GetScaleCallback(cros::mojom::DeviceType type,
                        const std::vector<std::optional<std::string>>& values);
  void OnReadFailed(cros::mojom::DeviceType type);

  IioDeviceHandler* accel_;
  IioDeviceHandler* gyro_;

  base::WeakPtrFactory<SensorDeviceFusionGravity> weak_factory_{this};
};

}  // namespace iioservice

#endif  // IIOSERVICE_DAEMON_SENSOR_DEVICE_FUSION_GRAVITY_H_
