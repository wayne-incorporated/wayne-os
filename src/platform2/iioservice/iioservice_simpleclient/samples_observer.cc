// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/iioservice_simpleclient/samples_observer.h"

#include <algorithm>
#include <iostream>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/time/time.h>
#include <libmems/common_types.h>

#include "iioservice/include/common.h"

namespace iioservice {

// static
SamplesObserver::ScopedSamplesObserver SamplesObserver::Create(
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    int device_id,
    cros::mojom::DeviceType device_type,
    std::vector<std::string> channel_ids,
    double frequency,
    int timeout,
    int samples,
    QuitCallback quit_callback) {
  ScopedSamplesObserver observer(
      new SamplesObserver(ipc_task_runner, device_id, device_type,
                          std::move(channel_ids), frequency, timeout, samples,
                          std::move(quit_callback)),
      SensorClientDeleter);

  return observer;
}

void SamplesObserver::OnSampleUpdated(
    const base::flat_map<int32_t, int64_t>& sample) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  DCHECK_GT(result_freq_, 0.0);

  if (sample.size() != channel_indices_.size()) {
    LOGF(ERROR) << "Invalid sample size: " << sample.size()
                << ", expected size: " << channel_indices_.size();
  }

  for (auto chn : sample)
    LOGF(INFO) << iio_chn_ids_[chn.first] << ": " << chn.second;

  if (timestamp_index_.has_value()) {
    auto it = sample.find(timestamp_index_.value());
    if (it != sample.end())
      AddTimestamp(it->second);
  }

  AddSuccessRead();
}

void SamplesObserver::OnErrorOccurred(cros::mojom::ObserverErrorType type) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  // Don't Change: Used as a check sentence in the tast test.
  LOGF(ERROR) << "OnErrorOccurred: " << type;
  Reset();
}

SamplesObserver::SamplesObserver(
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    int device_id,
    cros::mojom::DeviceType device_type,
    std::vector<std::string> channel_ids,
    double frequency,
    int timeout,
    int samples,
    QuitCallback quit_callback)
    : Observer(std::move(ipc_task_runner),
               std::move(quit_callback),
               device_id,
               device_type,
               samples),
      channel_ids_(std::move(channel_ids)),
      frequency_(frequency),
      timeout_(timeout),
      receiver_(this) {}

void SamplesObserver::Reset() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  sensor_device_remote_.reset();
  receiver_.reset();

  SensorClient::Reset();
}

mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver>
SamplesObserver::GetRemote() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  auto remote = receiver_.BindNewPipeAndPassRemote();
  receiver_.set_disconnect_handler(base::BindOnce(
      &SamplesObserver::OnObserverDisconnect, weak_factory_.GetWeakPtr()));

  return remote;
}

void SamplesObserver::GetSensorDevice() {
  Observer::GetSensorDevice();

  GetAllChannelIds();
}

void SamplesObserver::GetAllChannelIds() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  sensor_device_remote_->GetAllChannelIds(base::BindOnce(
      &SamplesObserver::GetAllChannelIdsCallback, weak_factory_.GetWeakPtr()));
}

void SamplesObserver::GetAllChannelIdsCallback(
    const std::vector<std::string>& iio_chn_ids) {
  iio_chn_ids_ = std::move(iio_chn_ids);
  channel_indices_.clear();

  for (int32_t i = 0; i < channel_ids_.size(); ++i) {
    for (int32_t j = 0; j < iio_chn_ids_.size(); ++j) {
      if (channel_ids_[i] == iio_chn_ids_[j]) {
        channel_indices_.push_back(j);
        break;
      }
    }
  }

  for (int32_t j = 0; j < iio_chn_ids_.size(); ++j) {
    if (iio_chn_ids_[j].compare(libmems::kTimestampAttr) == 0) {
      timestamp_index_ = j;
      break;
    }
  }

  if (channel_indices_.empty()) {
    LOGF(ERROR) << "No available channels";
    Reset();

    return;
  }

  StartReading();
}

void SamplesObserver::StartReading() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  sensor_device_remote_->SetTimeout(timeout_);
  sensor_device_remote_->SetFrequency(
      frequency_, base::BindOnce(&SamplesObserver::SetFrequencyCallback,
                                 weak_factory_.GetWeakPtr()));
  sensor_device_remote_->SetChannelsEnabled(
      channel_indices_, true,
      base::BindOnce(&SamplesObserver::SetChannelsEnabledCallback,
                     weak_factory_.GetWeakPtr()));

  sensor_device_remote_->StartReadingSamples(GetRemote());
}

void SamplesObserver::SetFrequencyCallback(double result_freq) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  result_freq_ = result_freq;
  if (result_freq_ > 0.0)
    return;

  LOGF(ERROR) << "Failed to set frequency";
  Reset();
}

void SamplesObserver::SetChannelsEnabledCallback(
    const std::vector<int32_t>& failed_indices) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  for (int32_t index : failed_indices) {
    LOGF(ERROR) << "Failed channel index: " << index;
    bool found = false;
    for (auto it = channel_indices_.begin(); it != channel_indices_.end();
         ++it) {
      if (index == *it) {
        found = true;
        channel_indices_.erase(it);
        break;
      }
    }

    if (!found)
      LOGF(ERROR) << index << " not in requested indices";
  }

  if (channel_indices_.empty()) {
    LOGF(ERROR) << "No channel enabled";
    Reset();
  }
}

base::TimeDelta SamplesObserver::GetLatencyTolerance() const {
  return Observer::GetLatencyTolerance() + base::Seconds(1.0 / result_freq_);
}

}  // namespace iioservice
