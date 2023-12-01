// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/iioservice_simpleclient/observer.h"

#include <utility>

#include <base/functional/bind.h>
#include <base/time/time.h>

#include "iioservice/include/common.h"

namespace iioservice {

namespace {

// Set the base latency tolerance to half of 100 ms, according to
// https://source.android.com/compatibility/android-cdd#7_3_sensors, as the
// samples may go through a VM and Android sensormanager.
constexpr base::TimeDelta kMaximumBaseLatencyTolerance = base::Milliseconds(50);

}  // namespace

Observer::Observer(scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
                   QuitCallback quit_callback,
                   int device_id,
                   cros::mojom::DeviceType device_type,
                   int num)
    : SensorClient(std::move(ipc_task_runner), std::move(quit_callback)),
      device_id_(device_id),
      device_type_(device_type),
      num_(num) {}

void Observer::Start() {
  if (device_id_ < 0)
    GetDeviceIdsByType();
  else
    GetSensorDevice();
}

void Observer::OnDeviceDisconnect() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  LOGF(ERROR) << "SensorDevice disconnected";
  Reset();
}

void Observer::OnObserverDisconnect() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  LOGF(ERROR) << "Observer diconnected";
  Reset();
}

void Observer::GetDeviceIdsByType() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  DCHECK_NE(device_type_, cros::mojom::DeviceType::NONE);

  sensor_service_remote_->GetDeviceIds(
      device_type_, base::BindOnce(&Observer::GetDeviceIdsCallback,
                                   weak_factory_.GetWeakPtr()));
}

void Observer::GetDeviceIdsCallback(
    const std::vector<int32_t>& iio_device_ids) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  if (iio_device_ids.empty()) {
    LOGF(ERROR) << "No device found give device type: " << device_type_;
    Reset();
  }

  // Take the first id.
  device_id_ = iio_device_ids.front();
  GetSensorDevice();
}

void Observer::GetSensorDevice() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  if (!sensor_device_remote_.is_bound()) {
    sensor_service_remote_->GetDevice(
        device_id_, sensor_device_remote_.BindNewPipeAndPassReceiver());

    sensor_device_remote_.set_disconnect_handler(base::BindOnce(
        &Observer::OnDeviceDisconnect, weak_factory_.GetWeakPtr()));
  }
}

void Observer::AddTimestamp(int64_t timestamp) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  struct timespec ts = {};
  if (clock_gettime(CLOCK_BOOTTIME, &ts) < 0) {
    PLOGF(ERROR) << "clock_gettime(CLOCK_BOOTTIME) failed";
    return;
  }

  auto latency =
      base::Nanoseconds(static_cast<int64_t>(ts.tv_sec) * 1000 * 1000 * 1000 +
                        ts.tv_nsec - timestamp);
  LOGF(INFO) << "Latency: " << latency;
  total_latency_ += latency;
  latencies_.push_back(latency);
}

void Observer::AddSuccessRead() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  if (++num_success_reads_ < num_)
    return;

  // Don't Change: Used as a check sentence in the tast test.
  LOGF(INFO) << "Number of success reads " << num_ << " achieved";

  // Calculate the latencies only when timestamp channel is enabled.
  if (!latencies_.empty()) {
    base::TimeDelta latency_tolerance = GetLatencyTolerance();

    size_t n = latencies_.size();
    std::nth_element(latencies_.begin(), latencies_.begin(), latencies_.end());
    base::TimeDelta min_latency = latencies_[0];

    std::nth_element(latencies_.begin(), latencies_.begin() + n / 2,
                     latencies_.end());
    base::TimeDelta median_latency = latencies_[n / 2];

    std::nth_element(latencies_.begin(), --latencies_.end(), latencies_.end());
    base::TimeDelta max_latency = *(--latencies_.end());

    if (max_latency > latency_tolerance) {
      // Don't Change: Used as a check sentence in the tast test.
      LOGF(ERROR) << "Max latency exceeds latency tolerance.";
      LOGF(ERROR) << "Latency tolerance: " << latency_tolerance;
      LOGF(ERROR) << "Max latency      : " << max_latency;
    } else {
      LOGF(INFO) << "Latency tolerance: " << latency_tolerance;
      LOGF(INFO) << "Max latency      : " << max_latency;
    }

    if (min_latency < base::Seconds(0.0)) {
      // Don't Change: Used as a check sentence in the tast test.
      LOGF(ERROR)
          << "Min latency less than zero: a timestamp was set in the past.";
      LOGF(ERROR) << "Min latency      : " << min_latency;
    } else {
      LOGF(INFO) << "Min latency      : " << min_latency;
    }

    LOGF(INFO) << "Median latency   : " << median_latency;
    LOGF(INFO) << "Mean latency     : " << total_latency_ / n;
  }

  Reset();
}

base::TimeDelta Observer::GetLatencyTolerance() const {
  return kMaximumBaseLatencyTolerance;
}

}  // namespace iioservice
