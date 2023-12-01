/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_SENSOR_READER_H_
#define CAMERA_COMMON_SENSOR_READER_H_

#include <optional>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <base/task/single_thread_task_runner.h>
#include <iioservice/mojo/sensor.mojom.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "cros-camera/sensor_hal_client.h"

namespace cros {

class SensorReader : public mojom::SensorDeviceSamplesObserver {
 public:
  static constexpr int kNumberOfAxes = 3;

  SensorReader(scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner,
               int32_t iio_device_id,
               cros::mojom::DeviceType type,
               double frequency,
               double scale,
               SamplesObserver* samples_observer,
               mojo::Remote<mojom::SensorDevice> remote);
  ~SensorReader() override;

  // SensorDeviceSamplesObserver Mojo interface implementation.
  void OnSampleUpdated(const base::flat_map<int32_t, int64_t>& sample) override;
  void OnErrorOccurred(mojom::ObserverErrorType type) override;

 private:
  void ResetOnError();

  void OnSensorDeviceDisconnect();

  double GetScaledValue(int64_t value);

  void GetAllChannelIdsCallback(
      const std::vector<std::string>& iio_channel_ids);
  void SetChannelsEnabled();
  void SetChannelsEnabledCallback(const std::vector<int32_t>& failed_indices);
  void SetFrequencyCallback(double result_freq);

  void OnReadFailure();

  // The Mojo IPC task runner.
  const scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;
  int32_t iio_device_id_;
  cros::mojom::DeviceType type_;
  double frequency_;
  double scale_;
  SamplesObserver* samples_observer_;
  mojo::Remote<mojom::SensorDevice> sensor_device_remote_;

  std::optional<int32_t> channel_indices_[kNumberOfAxes];
  std::optional<int32_t> timestamp_index_;

  mojo::Receiver<mojom::SensorDeviceSamplesObserver> receiver_{this};

  base::WeakPtrFactory<SensorReader> weak_ptr_factory_{this};
};

}  // namespace cros

#endif  // CAMERA_COMMON_SENSOR_READER_H_
