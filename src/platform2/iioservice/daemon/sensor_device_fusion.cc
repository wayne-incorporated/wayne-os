// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/daemon/sensor_device_fusion.h"

#include <optional>
#include <utility>

#include <base/strings/stringprintf.h>
#include <libmems/common_types.h>

#include "iioservice/daemon/sensor_metrics.h"
#include "iioservice/include/common.h"

namespace iioservice {

void SensorDeviceFusion::SensorDeviceFusionDeleter(SensorDeviceFusion* device) {
  if (device == nullptr)
    return;

  if (!device->ipc_task_runner_->RunsTasksInCurrentSequence()) {
    device->ipc_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&SensorDeviceFusion::SensorDeviceFusionDeleter, device));
    return;
  }

  delete device;
}

void SensorDeviceFusion::AddReceiver(
    mojo::PendingReceiver<cros::mojom::SensorDevice> request) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  mojo::ReceiverId id =
      receiver_set_.Add(this, std::move(request), ipc_task_runner_);

  clients_.emplace(id, ClientData(id));
}

void SensorDeviceFusion::SetTimeout(uint32_t timeout) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  mojo::ReceiverId id = receiver_set_.current_receiver();
  auto it = clients_.find(id);
  if (it == clients_.end())
    return;

  it->second.timeout = timeout;
}

void SensorDeviceFusion::SetFrequency(double frequency,
                                      SetFrequencyCallback callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(samples_handler_);

  if (invalid_) {
    std::move(callback).Run(-1.0);
    return;
  }

  mojo::ReceiverId id = receiver_set_.current_receiver();
  auto it = clients_.find(id);
  if (it == clients_.end()) {
    std::move(callback).Run(-1.0);
    return;
  }

  frequency = FixFrequency(frequency);
  std::move(callback).Run(frequency);

  ClientData& client = it->second;
  if (client.samples_observer.is_bound()) {
    // Let |samples_handler_| update |client.frequency|.
    samples_handler_->UpdateFrequency(&client, frequency);
  } else {
    client.frequency = frequency;
  }
}

void SensorDeviceFusion::StartReadingSamples(
    mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver> observer) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(samples_handler_);

  mojo::ReceiverId id = receiver_set_.current_receiver();
  auto it = clients_.find(id);
  if (it == clients_.end())
    return;
  ClientData& client = it->second;

  samples_handler_->AddClient(&client, std::move(observer));
}

void SensorDeviceFusion::StopReadingSamples() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  mojo::ReceiverId id = receiver_set_.current_receiver();
  StopReadingSamplesOnClient(id);
}

void SensorDeviceFusion::GetAllChannelIds(GetAllChannelIdsCallback callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  std::move(callback).Run(channel_ids_);
}

void SensorDeviceFusion::SetChannelsEnabled(
    const std::vector<int32_t>& iio_chn_indices,
    bool en,
    SetChannelsEnabledCallback callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  if (invalid_) {
    std::move(callback).Run(iio_chn_indices);
    return;
  }

  mojo::ReceiverId id = receiver_set_.current_receiver();
  auto it = clients_.find(id);
  if (it == clients_.end()) {
    LOGF(ERROR) << "Failed to find clients with id: " << id;
    std::move(callback).Run(iio_chn_indices);
    return;
  }

  ClientData& client = it->second;

  if (en) {
    for (int32_t chn_index : iio_chn_indices)
      client.enabled_chn_indices.emplace(chn_index);
  } else {
    for (int32_t chn_index : iio_chn_indices)
      client.enabled_chn_indices.erase(chn_index);
  }

  std::move(callback).Run({});
}

void SensorDeviceFusion::GetChannelsEnabled(
    const std::vector<int32_t>& iio_chn_indices,
    GetChannelsEnabledCallback callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  mojo::ReceiverId id = receiver_set_.current_receiver();
  auto it = clients_.find(id);
  if (it == clients_.end()) {
    LOGF(ERROR) << "Failed to find clients with id: " << id;
    std::move(callback).Run(std::vector<bool>(iio_chn_indices.size(), false));
    return;
  }

  ClientData& client = it->second;

  // List of channels enabled.
  std::vector<bool> enabled;

  for (int32_t chn_index : iio_chn_indices) {
    enabled.push_back(client.enabled_chn_indices.find(chn_index) !=
                      client.enabled_chn_indices.end());
  }

  std::move(callback).Run(std::move(enabled));
}

void SensorDeviceFusion::GetAllEvents(GetAllEventsCallback callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  std::move(callback).Run({});
}

void SensorDeviceFusion::GetEventsAttributes(
    const std::vector<int32_t>& iio_event_indices,
    const std::string& attr_name,
    GetEventsAttributesCallback callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  std::move(callback).Run(std::vector<std::optional<std::string>>(
      iio_event_indices.size(), std::nullopt));
}

void SensorDeviceFusion::StartReadingEvents(
    const std::vector<int32_t>& iio_event_indices,
    mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver> observer) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  // Do nothing.
}

SensorDeviceFusion::IioDeviceHandler::IioDeviceHandler(
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    int32_t iio_device_id,
    cros::mojom::DeviceType type,
    base::RepeatingCallback<
        void(int32_t iio_device_id,
             mojo::PendingReceiver<cros::mojom::SensorDevice> request)>
        iio_add_receiver_callback,
    base::RepeatingCallback<void(std::vector<int64_t>)>
        on_sample_updated_callback,
    base::RepeatingCallback<void()> on_read_failed_callback,
    base::OnceCallback<void()> invalidate_callback)
    : ipc_task_runner_(std::move(ipc_task_runner)),
      iio_device_id_(iio_device_id),
      type_(type),
      on_sample_updated_callback_(std::move(on_sample_updated_callback)),
      on_read_failed_callback_(std::move(on_read_failed_callback)),
      invalidate_callback_(std::move(invalidate_callback)) {
  iio_add_receiver_callback.Run(iio_device_id_,
                                remote_.BindNewPipeAndPassReceiver());

  remote_.set_disconnect_handler(base::BindOnce(
      &SensorDeviceFusion::IioDeviceHandler::OnIioDeviceDisconnect,
      weak_factory_.GetWeakPtr()));

  SetChannelIds();
  remote_->GetAllChannelIds(base::BindOnce(
      &SensorDeviceFusion::IioDeviceHandler::GetAllChannelIdsCallback,
      weak_factory_.GetWeakPtr()));
}

void SensorDeviceFusion::IioDeviceHandler::SetAttribute(
    std::string attr_name, std::optional<std::string> attr_value) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  attributes_[attr_name] = attr_value;
}

void SensorDeviceFusion::IioDeviceHandler::SetFrequency(
    double frequency, base::OnceCallback<void(double)> callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  if (!remote_.is_bound())
    return;

  remote_->SetFrequency(
      frequency,
      base::BindOnce(
          &SensorDeviceFusion::IioDeviceHandler::SetFrequencyCallback,
          weak_factory_.GetWeakPtr(), frequency, std::move(callback)));
}

void SensorDeviceFusion::IioDeviceHandler::GetAttributes(
    const std::vector<std::string>& attr_names,
    cros::mojom::SensorDevice::GetAttributesCallback callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  if (!remote_.is_bound()) {
    GetAttributesCallback(attr_names, std::move(callback),
                          std::vector<std::optional<std::string>>(
                              attr_names.size(), std::nullopt));
    return;
  }

  remote_->GetAttributes(
      attr_names,
      base::BindOnce(
          &SensorDeviceFusion::IioDeviceHandler::GetAttributesCallback,
          weak_factory_.GetWeakPtr(), attr_names, std::move(callback)));
}

void SensorDeviceFusion::IioDeviceHandler::OnSampleUpdated(
    const base::flat_map<int32_t, int64_t>& sample) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  std::vector<int64_t> values;
  for (int32_t index : channel_indices_) {
    auto it = sample.find(index);
    if (it == sample.end()) {
      LOGF(ERROR) << "Couldn't find index: " << index
                  << ", in the sample of iio device with type: " << type_;
      on_read_failed_callback_.Run();
      return;
    }

    values.push_back(it->second);
  }

  on_sample_updated_callback_.Run(std::move(values));
}

void SensorDeviceFusion::IioDeviceHandler::OnErrorOccurred(
    cros::mojom::ObserverErrorType type) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  switch (type) {
    case cros::mojom::ObserverErrorType::ALREADY_STARTED:
      LOGF(ERROR) << "Device " << iio_device_id_
                  << ": Another observer has already started to read samples";
      Invalidate();
      break;

    case cros::mojom::ObserverErrorType::FREQUENCY_INVALID:
      // Ignore: We might start reading without a valid frequency set.
      break;

    case cros::mojom::ObserverErrorType::NO_ENABLED_CHANNELS:
      LOGF(ERROR) << "Device " << iio_device_id_
                  << ": Observer started with no channels enabled";
      Invalidate();
      break;

    case cros::mojom::ObserverErrorType::SET_FREQUENCY_IO_FAILED:
      LOGF(ERROR) << "Device " << iio_device_id_
                  << ": Failed to set frequency to the physical device";
      break;

    case cros::mojom::ObserverErrorType::GET_FD_FAILED:
      LOGF(ERROR) << "Device " << iio_device_id_
                  << ": Failed to get the device's fd to poll on";
      break;

    case cros::mojom::ObserverErrorType::READ_FAILED:
      LOGF(ERROR) << "Device " << iio_device_id_ << ": Failed to read a sample";
      on_read_failed_callback_.Run();
      break;

    case cros::mojom::ObserverErrorType::READ_TIMEOUT:
      LOGF(ERROR) << "Device " << iio_device_id_ << ": A read timed out";
      break;

    default:
      LOGF(ERROR) << "Device " << iio_device_id_ << ": error " << type;
      break;
  }
}

void SensorDeviceFusion::IioDeviceHandler::DisableSamples() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  if (remote_.is_bound())
    remote_->StopReadingSamples();

  receiver_.reset();

  invalidate_callback_.Reset();
}

void SensorDeviceFusion::IioDeviceHandler::Invalidate() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  if (invalidate_callback_)
    std::move(invalidate_callback_).Run();

  DisableSamples();
}

void SensorDeviceFusion::IioDeviceHandler::SetChannelIds() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  switch (type_) {
    case cros::mojom::DeviceType::ACCEL:
      for (char axis : kChannelAxes) {
        channel_ids_.push_back(base::StringPrintf(
            kChannelFormat, cros::mojom::kAccelerometerChannel, axis));
      }
      channel_ids_.push_back(cros::mojom::kTimestampChannel);
      break;

    case cros::mojom::DeviceType::ANGLVEL:
      for (char axis : kChannelAxes) {
        channel_ids_.push_back(base::StringPrintf(
            kChannelFormat, cros::mojom::kGyroscopeChannel, axis));
      }
      channel_ids_.push_back(cros::mojom::kTimestampChannel);
      break;

    default:
      break;
  }
}

void SensorDeviceFusion::IioDeviceHandler::OnIioDeviceDisconnect() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  LOGF(ERROR) << "OnIioDeviceDisconnect in fusion device with iio_device_id: "
              << iio_device_id_ << ", and iio device's type: " << type_;

  remote_.reset();
  Invalidate();
}

void SensorDeviceFusion::IioDeviceHandler::OnObserverDisconnect() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  LOGF(ERROR) << "OnObserverDisconnect in fusion device with iio_device_id: "
              << iio_device_id_ << ", and iio device's type: " << type_;

  Invalidate();
}

void SensorDeviceFusion::IioDeviceHandler::SetFrequencyCallback(
    double requested_frequency,
    cros::mojom::SensorDevice::SetFrequencyCallback callback,
    double result_frequency) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  if ((requested_frequency > 0 && result_frequency > 0) ||
      (requested_frequency <= 0 && result_frequency <= 0)) {
    if (callback)
      std::move(callback).Run(result_frequency);

    return;
  }

  LOGF(ERROR) << "Failed to set requested_frequency: " << requested_frequency;
  Invalidate();
}

void SensorDeviceFusion::IioDeviceHandler::GetAttributesCallback(
    const std::vector<std::string>& attr_names,
    cros::mojom::SensorDevice::GetAttributesCallback callback,
    const std::vector<std::optional<std::string>>& values) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  DCHECK_EQ(attr_names.size(), values.size());

  std::vector<std::optional<std::string>> overriden_values = values;
  for (size_t i = 0; i < attr_names.size(); ++i) {
    auto it = attributes_.find(attr_names[i]);
    if (it == attributes_.end())
      continue;

    overriden_values[i] = it->second;
  }

  std::move(callback).Run(std::move(overriden_values));
}

void SensorDeviceFusion::IioDeviceHandler::GetAllChannelIdsCallback(
    const std::vector<std::string>& iio_chn_ids) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(remote_.is_bound());
  // Should only be called once.
  DCHECK(!receiver_.is_bound());

  for (const auto& channel_id : channel_ids_) {
    bool found = false;
    for (int i = 0; i < iio_chn_ids.size(); ++i) {
      if (channel_id == iio_chn_ids[i]) {
        found = true;
        channel_indices_.push_back(i);
        break;
      }
    }

    if (!found) {
      LOGF(ERROR) << "Couldn't find channel with id: " << channel_id
                  << ", in the iio device with id: " << iio_device_id_;
      Invalidate();
      return;
    }
  }

  StartReading();
}

void SensorDeviceFusion::IioDeviceHandler::SetChannelsEnabledCallback(
    const std::vector<int32_t>& failed_indices) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  for (int32_t index : failed_indices) {
    LOGF(ERROR) << "Failed to enable channel with index: " << index
                << ", in iio device with id: " << iio_device_id_;
  }

  if (!failed_indices.empty())
    Invalidate();
}

void SensorDeviceFusion::IioDeviceHandler::StartReading() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(remote_.is_bound());
  DCHECK_EQ(channel_ids_.size(), channel_indices_.size());

  if (!invalidate_callback_) {
    // This handler has already been invalidated. No sample is required.
    return;
  }

  remote_->SetTimeout(0);
  remote_->SetChannelsEnabled(
      channel_indices_, true,
      base::BindOnce(
          &SensorDeviceFusion::IioDeviceHandler::SetChannelsEnabledCallback,
          weak_factory_.GetWeakPtr()));

  remote_->StartReadingSamples(receiver_.BindNewPipeAndPassRemote());
  receiver_.set_disconnect_handler(base::BindOnce(
      &SensorDeviceFusion::IioDeviceHandler::OnObserverDisconnect,
      weak_factory_.GetWeakPtr()));
}

SensorDeviceFusion::SensorDeviceFusion(
    int32_t id,
    cros::mojom::DeviceType type,
    Location location,
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    base::RepeatingCallback<
        void(int32_t iio_device_id,
             mojo::PendingReceiver<cros::mojom::SensorDevice> request)>
        iio_add_receiver_callback,
    double max_frequency,
    std::vector<std::string> channel_ids)
    : id_(id),
      type_(type),
      location_(location),
      ipc_task_runner_(std::move(ipc_task_runner)),
      iio_add_receiver_callback_(std::move(iio_add_receiver_callback)),
      max_frequency_(max_frequency),
      channel_ids_(std::move(channel_ids)) {
  receiver_set_.set_disconnect_handler(
      base::BindRepeating(&SensorDeviceFusion::OnSensorDeviceDisconnect,
                          weak_factory_.GetWeakPtr()));
}

void SensorDeviceFusion::Invalidate() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  LOGF(ERROR) << "Invalidating fusion device and prohibit settings and samples "
                 "with type: "
              << type_ << ", and location: " << location_;

  invalid_ = true;
  samples_handler_->Invalidate();
  for (auto& iio_device_handler : iio_device_handlers_)
    iio_device_handler->DisableSamples();
}

void SensorDeviceFusion::UpdateRequestedFrequency(double frequency) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  requested_frequency_ = frequency;
  SensorMetrics::GetInstance()->SendSensorUsage(id_, requested_frequency_);
}

void SensorDeviceFusion::OnSensorDeviceDisconnect() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  mojo::ReceiverId id = receiver_set_.current_receiver();

  LOGF(INFO) << "SensorDevice disconnected. ReceiverId: " << id;
  StopReadingSamplesOnClient(id);

  clients_.erase(id);
}

void SensorDeviceFusion::StopReadingSamplesOnClient(mojo::ReceiverId id) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(samples_handler_);

  auto it = clients_.find(id);
  if (it == clients_.end())
    return;

  ClientData& client = it->second;
  samples_handler_->RemoveClient(&client);
}

double SensorDeviceFusion::FixFrequency(double frequency) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  if (frequency < libmems::kFrequencyEpsilon)
    return 0.0;

  if (frequency > max_frequency_)
    return max_frequency_;

  return frequency;
}

double SensorDeviceFusion::FixFrequencyWithMin(double min_frequency,
                                               double frequency) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  if (frequency < libmems::kFrequencyEpsilon)
    return 0.0;

  if (frequency < min_frequency)
    return min_frequency;

  if (frequency > max_frequency_)
    return max_frequency_;

  return frequency;
}

}  // namespace iioservice
