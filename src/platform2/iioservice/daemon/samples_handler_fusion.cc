// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/daemon/samples_handler_fusion.h"

#include <utility>

#include <libmems/common_types.h>

#include "iioservice/daemon/sensor_metrics.h"
#include "iioservice/include/common.h"

namespace iioservice {

SamplesHandlerFusion::SamplesHandlerFusion(
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    std::vector<std::string> channel_ids,
    UpdateFrequencyCallback callback)
    : SamplesHandlerBase(ipc_task_runner),
      ipc_task_runner_(std::move(ipc_task_runner)),
      update_frequency_callback_(std::move(callback)) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  SetNoBatchChannels(std::move(channel_ids));
}

SamplesHandlerFusion::~SamplesHandlerFusion() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  update_frequency_callback_.Run(0.0);

  for (ClientData* client : inactive_clients_) {
    if (client->samples_observer.is_bound()) {
      SensorMetrics::GetInstance()->SendSensorObserverClosed();
      client->samples_observer.reset();
    }
  }

  for (auto& [client, _] : clients_map_) {
    if (client->samples_observer.is_bound()) {
      SensorMetrics::GetInstance()->SendSensorObserverClosed();
      client->samples_observer.reset();
    }
  }
}

void SamplesHandlerFusion::AddClient(
    ClientData* client_data,
    mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver> observer) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  if (invalid_) {
    DCHECK(!client_data->samples_observer.is_bound());
    client_data->samples_observer.Bind(std::move(observer));
    client_data->samples_observer.set_disconnect_handler(
        base::BindOnce(&SamplesHandlerFusion::OnSamplesObserverDisconnect,
                       GetWeakPtr(), client_data));

    client_data->samples_observer->OnErrorOccurred(
        cros::mojom::ObserverErrorType::FREQUENCY_INVALID);
    return;
  }

  AddClientOnThread(client_data, std::move(observer));
}

void SamplesHandlerFusion::RemoveClient(ClientData* client_data) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  if (invalid_)
    return;

  SamplesHandlerBase::RemoveClientOnThread(client_data);
}

void SamplesHandlerFusion::UpdateFrequency(ClientData* client_data,
                                           double frequency) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  if (invalid_)
    return;

  double orig_freq = client_data->frequency;
  client_data->frequency = frequency;

  auto it = inactive_clients_.find(client_data);
  if (it != inactive_clients_.end()) {
    if (client_data->IsSampleActive()) {
      // The client is now active.
      inactive_clients_.erase(it);
      AddActiveClientOnThread(client_data);
    }

    return;
  }

  if (clients_map_.find(client_data) == clients_map_.end()) {
    LOGF(WARNING) << "Client with ReceiverId: " << client_data->id
                  << " doesn't exist in SamplesHandlerFusion";
    return;
  }

  if (!client_data->IsSampleActive()) {
    // The client is now inactive
    RemoveActiveClientOnThread(client_data, orig_freq);
    inactive_clients_.emplace(client_data);

    return;
  }

  // The client remains active
  DCHECK(client_data->samples_observer.is_bound());

  AddFrequencyOnThread(client_data->frequency);
  RemoveFrequencyOnThread(orig_freq);
}

void SamplesHandlerFusion::Invalidate() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  invalid_ = true;

  frequencies_.clear();
  update_frequency_callback_.Run(GetRequestedFrequencyOnThread());  // 0.0

  for (ClientData* client : inactive_clients_) {
    if (client->samples_observer.is_bound())
      SensorMetrics::GetInstance()->SendSensorObserverClosed();
  }

  inactive_clients_.clear();

  for (auto& [client_data, _] : clients_map_) {
    DCHECK(client_data->samples_observer.is_bound());

    SensorMetrics::GetInstance()->SendSensorObserverClosed();

    client_data->samples_observer->OnErrorOccurred(
        cros::mojom::ObserverErrorType::FREQUENCY_INVALID);
  }

  clients_map_.clear();
}

bool SamplesHandlerFusion::UpdateRequestedFrequencyOnThread() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  double frequency = GetRequestedFrequencyOnThread();
  if (frequency == requested_frequency_)
    return true;

  requested_frequency_ = frequency;
  update_frequency_callback_.Run(requested_frequency_);
  return true;
}

void SamplesHandlerFusion::OnSampleAvailableOnThread(
    const base::flat_map<int32_t, int64_t>& sample) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  if (!SampleIsValid(sample)) {
    AddReadFailedLogOnThread();
    for (auto& [client_data, _] : clients_map_) {
      client_data->samples_observer->OnErrorOccurred(
          cros::mojom::ObserverErrorType::READ_FAILED);
    }

    return;
  }

  SamplesHandlerBase::OnSampleAvailableOnThread(sample);
}

bool SamplesHandlerFusion::SampleIsValid(
    const base::flat_map<int32_t, int64_t>& sample) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  return !sample.empty();
}

}  // namespace iioservice
