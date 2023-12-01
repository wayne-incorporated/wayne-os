// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_IIOSERVICE_SIMPLECLIENT_SAMPLES_OBSERVER_H_
#define IIOSERVICE_IIOSERVICE_SIMPLECLIENT_SAMPLES_OBSERVER_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/task/sequenced_task_runner.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "iioservice/iioservice_simpleclient/observer.h"
#include "iioservice/mojo/cros_sensor_service.mojom.h"
#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

class SamplesObserver final : public Observer,
                              public cros::mojom::SensorDeviceSamplesObserver {
 public:
  using ScopedSamplesObserver =
      std::unique_ptr<SamplesObserver, decltype(&SensorClientDeleter)>;

  // The task runner should be the same as the one provided to SensorClient.
  static ScopedSamplesObserver Create(
      scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
      int device_id,
      cros::mojom::DeviceType device_type,
      std::vector<std::string> channel_ids,
      double frequency,
      int timeout,
      int samples,
      QuitCallback quit_callback);

  // cros::mojom::SensorDeviceSamplesObserver overrides:
  void OnSampleUpdated(const base::flat_map<int32_t, int64_t>& sample) override;
  void OnErrorOccurred(cros::mojom::ObserverErrorType type) override;

 private:
  SamplesObserver(scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
                  int device_id,
                  cros::mojom::DeviceType device_type,
                  std::vector<std::string> channel_ids,
                  double frequency,
                  int timeout,
                  int samples,
                  QuitCallback quit_callback);

  // SensorClient overrides:
  void Reset() override;

  mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver> GetRemote();

  void GetSensorDevice() override;

  void GetAllChannelIds();
  void GetAllChannelIdsCallback(const std::vector<std::string>& iio_chn_ids);

  void StartReading();

  void SetFrequencyCallback(double result_freq);
  void SetChannelsEnabledCallback(const std::vector<int32_t>& failed_indices);

  base::TimeDelta GetLatencyTolerance() const override;

  const std::vector<std::string> channel_ids_;
  double frequency_;
  double result_freq_ = 0.0;
  int timeout_;

  std::vector<int32_t> channel_indices_;
  std::vector<std::string> iio_chn_ids_;

  std::optional<int> timestamp_index_ = std::nullopt;

  mojo::Receiver<cros::mojom::SensorDeviceSamplesObserver> receiver_;

  base::WeakPtrFactory<SamplesObserver> weak_factory_{this};
};

}  // namespace iioservice

#endif  // IIOSERVICE_IIOSERVICE_SIMPLECLIENT_SAMPLES_OBSERVER_H_
