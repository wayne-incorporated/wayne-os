// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/daemon/sensor_device_impl.h"

#include <optional>
#include <utility>

#include <base/check.h>
#include <base/containers/contains.h>
#include <base/functional/bind.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <libmems/common_types.h>
#include <libmems/iio_channel.h>

#include "iioservice/include/common.h"

namespace iioservice {

namespace {

constexpr char kDeviceRemovedDescription[] = "Device was removed";

const std::vector<cros::mojom::DeviceType> kMotionSensors = {
    cros::mojom::DeviceType::ACCEL, cros::mojom::DeviceType::ANGLVEL,
    cros::mojom::DeviceType::MAGN};

constexpr char kChannelAttributeFormat[] = "in_%s_%s";

}  // namespace

// static
void SensorDeviceImpl::SensorDeviceImplDeleter(SensorDeviceImpl* device) {
  if (device == nullptr)
    return;

  if (!device->ipc_task_runner_->RunsTasksInCurrentSequence()) {
    device->ipc_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&SensorDeviceImpl::SensorDeviceImplDeleter, device));
    return;
  }

  delete device;
}

// static
SensorDeviceImpl::ScopedSensorDeviceImpl SensorDeviceImpl::Create(
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    libmems::IioContext* context) {
  DCHECK(ipc_task_runner->RunsTasksInCurrentSequence());

  ScopedSensorDeviceImpl device(nullptr, SensorDeviceImplDeleter);

  std::unique_ptr<base::Thread> thread(new base::Thread("SensorDeviceImpl"));
  if (!thread->StartWithOptions(
          base::Thread::Options(base::MessagePumpType::IO, 0))) {
    LOGF(ERROR) << "Failed to start thread with TYPE_IO";
    device.reset();
    return device;
  }

  device.reset(new SensorDeviceImpl(std::move(ipc_task_runner), context,
                                    std::move(thread)));

  return device;
}

SensorDeviceImpl::~SensorDeviceImpl() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  samples_handlers_.clear();
  sample_thread_->Stop();
  receiver_set_.Clear();
  clients_.clear();
}

void SensorDeviceImpl::OnDeviceAdded(
    libmems::IioDevice* iio_device,
    const std::set<cros::mojom::DeviceType>& types) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  devices_.emplace(iio_device->GetId(), DeviceData(iio_device, types));
}

void SensorDeviceImpl::OnDeviceRemoved(int iio_device_id) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  // Remove SensorDevice clients to prevent further mojo requests.
  for (auto it = clients_.begin(); it != clients_.end(); ++it) {
    if (it->second.device_data->iio_device_id == iio_device_id) {
      receiver_set_.RemoveWithReason(
          it->first,
          static_cast<uint32_t>(
              cros::mojom::SensorDeviceDisconnectReason::DEVICE_REMOVED),
          kDeviceRemovedDescription);
    }
  }

  auto it_handler = samples_handlers_.find(iio_device_id);
  if (it_handler != samples_handlers_.end()) {
    it_handler->second->ResetWithReason(
        cros::mojom::SensorDeviceDisconnectReason::DEVICE_REMOVED,
        kDeviceRemovedDescription,
        base::BindOnce(&SensorDeviceImpl::OnDeviceRemoved,
                       weak_factory_.GetWeakPtr(), iio_device_id));
    samples_handlers_.erase(it_handler);
    // |OnDeviceRemoved| will be called again after SensorDeviceSamplesObserver
    // mojo pipes are reset in |sample_thread_|.
    return;
  }

  for (auto it = clients_.begin(); it != clients_.end();) {
    if (it->second.device_data->iio_device_id == iio_device_id)
      it = clients_.erase(it);
    else
      ++it;
  }

  devices_.erase(iio_device_id);
}

void SensorDeviceImpl::AddReceiver(
    int32_t iio_device_id,
    mojo::PendingReceiver<cros::mojom::SensorDevice> request) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  auto it = devices_.find(iio_device_id);
  if (it == devices_.end()) {
    LOGF(ERROR) << "Invalid iio_device_id: " << iio_device_id;
    return;
  }

  mojo::ReceiverId id =
      receiver_set_.Add(this, std::move(request), ipc_task_runner_);

  clients_.emplace(id, ClientData(id, &it->second));
}

void SensorDeviceImpl::SetTimeout(uint32_t timeout) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  mojo::ReceiverId id = receiver_set_.current_receiver();
  auto it = clients_.find(id);
  if (it == clients_.end())
    return;

  it->second.timeout = timeout;
}

void SensorDeviceImpl::GetAttributes(const std::vector<std::string>& attr_names,
                                     GetAttributesCallback callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  mojo::ReceiverId id = receiver_set_.current_receiver();
  auto it = clients_.find(id);
  if (it == clients_.end()) {
    LOGF(ERROR) << "Failed to find clients with id: " << id;
    std::move(callback).Run(std::vector<std::optional<std::string>>(
        attr_names.size(), std::nullopt));
    return;
  }

  ClientData& client = it->second;

  std::vector<std::optional<std::string>> values;
  values.reserve(attr_names.size());
  for (const auto& attr_name : attr_names) {
    std::optional<std::string> value_opt;
    if (attr_name == cros::mojom::kSysPath) {
      auto path_opt = client.device_data->iio_device->GetAbsoluteSysPath();
      if (path_opt.has_value())
        value_opt = path_opt.value().value();
    } else if (attr_name == cros::mojom::kLocation) {
      value_opt = client.device_data->iio_device->GetLocation();
    } else if (attr_name == cros::mojom::kDevlink) {
      auto path_opt = client.device_data->iio_device->GetAbsoluteSysPath();
      if (path_opt.has_value() &&
          base::Contains(client.device_data->types,
                         cros::mojom::DeviceType::PROXIMITY)) {
        value_opt = libmems::GetIioSarSensorDevlink(path_opt.value().value());
      }
    } else {
      value_opt =
          client.device_data->iio_device->ReadStringAttribute(attr_name);
    }

    if (!value_opt.has_value()) {
      // Look for channels' attributes instead.
      for (auto type : client.device_data->types) {
        auto type_in_string = DeviceTypeToString(type);
        if (!type_in_string.has_value())
          continue;

        value_opt = client.device_data->iio_device->ReadStringAttribute(
            base::StringPrintf(kChannelAttributeFormat, type_in_string->c_str(),
                               attr_name.c_str()));

        if (value_opt.has_value())
          break;
      }
    }

    if (!value_opt.has_value()) {
      if (attr_name == cros::mojom::kLocation) {
        std::optional<cros::mojom::DeviceType> type;
        for (auto& t : kMotionSensors) {
          if (base::Contains(client.device_data->types, t)) {
            type = t;
            break;
          }
        }

        if (type.has_value()) {
          std::optional<int32_t> only_device_id;
          for (auto& device : devices_) {
            if (base::Contains(device.second.types, type.value()) &&
                device.second.on_dut) {
              if (!only_device_id.has_value()) {
                only_device_id = device.first;
              } else {
                only_device_id = std::nullopt;
                break;
              }
            }
          }

          if (only_device_id.has_value() &&
              only_device_id == client.device_data->iio_device_id) {
            // It's the only motion sensor type on dut. Assume it on location
            // lid.
            value_opt = cros::mojom::kLocationLid;
          }
        }
      }
    }

    values.push_back(std::move(value_opt));
  }

  std::move(callback).Run(std::move(values));
}

void SensorDeviceImpl::SetFrequency(double frequency,
                                    SetFrequencyCallback callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  mojo::ReceiverId id = receiver_set_.current_receiver();
  auto it = clients_.find(id);
  if (it == clients_.end()) {
    LOGF(ERROR) << "Failed to find clients with id: " << id;
    std::move(callback).Run(-1.0);
    return;
  }

  ClientData& client = it->second;

  auto it_handler = samples_handlers_.find(client.device_data->iio_device_id);
  if (it_handler != samples_handlers_.end()) {
    it_handler->second->UpdateFrequency(&client, frequency,
                                        std::move(callback));
    return;
  }

  client.frequency = frequency;
  std::move(callback).Run(frequency);
}

void SensorDeviceImpl::StartReadingSamples(
    mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver> observer) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  mojo::ReceiverId id = receiver_set_.current_receiver();
  auto it = clients_.find(id);
  if (it == clients_.end()) {
    LOGF(ERROR) << "Failed to find clients with id: " << id;
    return;
  }

  ClientData& client = it->second;

  if (samples_handlers_.find(client.device_data->iio_device_id) ==
      samples_handlers_.end()) {
    SamplesHandler::ScopedSamplesHandler handler = {
        nullptr, SamplesHandler::SamplesHandlerDeleter};

    handler = SamplesHandler::Create(
        ipc_task_runner_, sample_thread_->task_runner(), client.device_data);

    if (!handler) {
      LOGF(ERROR) << "Failed to create the samples handler for device: "
                  << client.device_data->iio_device_id;
      return;
    }

    samples_handlers_.emplace(client.device_data->iio_device_id,
                              std::move(handler));
  }

  samples_handlers_.at(client.device_data->iio_device_id)
      ->AddClient(&client, std::move(observer));
}

void SensorDeviceImpl::StopReadingSamples() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  mojo::ReceiverId id = receiver_set_.current_receiver();
  StopReadingSamplesOnClient(id, base::DoNothing());
}

void SensorDeviceImpl::GetAllChannelIds(GetAllChannelIdsCallback callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  mojo::ReceiverId id = receiver_set_.current_receiver();
  auto it = clients_.find(id);
  if (it == clients_.end()) {
    LOGF(ERROR) << "Failed to find clients with id: " << id;
    std::move(callback).Run({});
    return;
  }

  auto iio_device = it->second.device_data->iio_device;
  std::vector<std::string> chn_ids;
  for (auto iio_channel : iio_device->GetAllChannels())
    chn_ids.push_back(iio_channel->GetId());

  std::move(callback).Run(std::move(chn_ids));
}

void SensorDeviceImpl::SetChannelsEnabled(
    const std::vector<int32_t>& iio_chn_indices,
    bool en,
    SetChannelsEnabledCallback callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  mojo::ReceiverId id = receiver_set_.current_receiver();
  auto it = clients_.find(id);
  if (it == clients_.end()) {
    LOGF(ERROR) << "Failed to find clients with id: " << id;
    std::move(callback).Run(iio_chn_indices);
    return;
  }

  ClientData& client = it->second;

  auto it_handler = samples_handlers_.find(client.device_data->iio_device_id);
  if (it_handler != samples_handlers_.end()) {
    it_handler->second->UpdateChannelsEnabled(
        &client, std::move(iio_chn_indices), en, std::move(callback));
    return;
  }

  if (en) {
    for (int32_t chn_index : iio_chn_indices)
      client.enabled_chn_indices.emplace(chn_index);
  } else {
    for (int32_t chn_index : iio_chn_indices)
      client.enabled_chn_indices.erase(chn_index);
  }

  std::move(callback).Run({});
}

void SensorDeviceImpl::GetChannelsEnabled(
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

  auto it_handler = samples_handlers_.find(client.device_data->iio_device_id);
  if (it_handler != samples_handlers_.end()) {
    it_handler->second->GetChannelsEnabled(&client, std::move(iio_chn_indices),
                                           std::move(callback));
    return;
  }

  // List of channels enabled.
  std::vector<bool> enabled;

  for (int32_t chn_index : iio_chn_indices) {
    enabled.push_back(client.enabled_chn_indices.find(chn_index) !=
                      client.enabled_chn_indices.end());
  }

  std::move(callback).Run(std::move(enabled));
}

void SensorDeviceImpl::GetChannelsAttributes(
    const std::vector<int32_t>& iio_chn_indices,
    const std::string& attr_name,
    GetChannelsAttributesCallback callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  mojo::ReceiverId id = receiver_set_.current_receiver();
  auto it = clients_.find(id);
  if (it == clients_.end()) {
    LOGF(ERROR) << "Failed to find clients with id: " << id;
    std::move(callback).Run(std::vector<std::optional<std::string>>(
        iio_chn_indices.size(), std::nullopt));
    return;
  }

  ClientData& client = it->second;
  auto iio_device = client.device_data->iio_device;

  std::vector<std::optional<std::string>> values;

  for (int32_t chn_index : iio_chn_indices) {
    auto chn = iio_device->GetChannel(chn_index);

    if (!chn) {
      LOGF(ERROR) << "Cannot find chn with index: " << chn_index;
      values.push_back(std::nullopt);
      continue;
    }

    std::optional<std::string> value_opt = chn->ReadStringAttribute(attr_name);

    values.push_back(value_opt);
  }

  std::move(callback).Run(std::move(values));
}

void SensorDeviceImpl::GetAllEvents(GetAllEventsCallback callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  mojo::ReceiverId id = receiver_set_.current_receiver();
  auto it = clients_.find(id);
  if (it == clients_.end()) {
    LOGF(ERROR) << "Failed to find clients with id: " << id;
    std::move(callback).Run({});
    return;
  }

  ClientData& client = it->second;
  auto iio_device = client.device_data->iio_device;

  std::vector<cros::mojom::IioEventPtr> events;
  for (auto* event : iio_device->GetAllEvents()) {
    events.push_back(
        cros::mojom::IioEvent::New(ConvertChanType(event->GetChannelType()),
                                   ConvertEventType(event->GetEventType()),
                                   ConvertDirection(event->GetDirection()),
                                   event->GetChannelNumber(), 0LL));
  }

  std::move(callback).Run(std::move(events));
}

void SensorDeviceImpl::GetEventsAttributes(
    const std::vector<int32_t>& iio_event_indices,
    const std::string& attr_name,
    GetEventsAttributesCallback callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  mojo::ReceiverId id = receiver_set_.current_receiver();
  auto it = clients_.find(id);
  if (it == clients_.end()) {
    LOGF(ERROR) << "Failed to find clients with id: " << id;
    std::move(callback).Run(std::vector<std::optional<std::string>>(
        iio_event_indices.size(), std::nullopt));
    return;
  }

  ClientData& client = it->second;
  auto iio_device = client.device_data->iio_device;

  std::vector<std::optional<std::string>> values;

  for (int32_t event_index : iio_event_indices) {
    auto event = iio_device->GetChannel(event_index);

    if (!event) {
      LOGF(ERROR) << "Cannot find event with index: " << event_index;
      values.push_back(std::nullopt);
      continue;
    }

    std::optional<std::string> value_opt =
        event->ReadStringAttribute(attr_name);
    if (value_opt.has_value()) {
      value_opt = std::string(base::TrimString(value_opt.value(),
                                               base::StringPiece("\0\n", 2),
                                               base::TRIM_TRAILING));
    }

    values.push_back(value_opt);
  }

  std::move(callback).Run(std::move(values));
}

void SensorDeviceImpl::StartReadingEvents(
    const std::vector<int32_t>& iio_event_indices,
    mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver> observer) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  mojo::ReceiverId id = receiver_set_.current_receiver();
  auto it = clients_.find(id);
  if (it == clients_.end()) {
    LOGF(ERROR) << "Failed to find clients with id: " << id;
    return;
  }

  ClientData& client = it->second;

  if (iio_event_indices.empty()) {
    mojo::Remote<cros::mojom::SensorDeviceEventsObserver>(std::move(observer))
        ->OnErrorOccurred(cros::mojom::ObserverErrorType::ALREADY_STARTED);
    return;
  }

  if (!base::Contains(events_handlers_, client.device_data->iio_device_id)) {
    EventsHandler::ScopedEventsHandler handler = {
        nullptr, EventsHandler::EventsHandlerDeleter};

    handler =
        EventsHandler::Create(ipc_task_runner_, sample_thread_->task_runner(),
                              client.device_data->iio_device);

    if (!handler) {
      LOGF(ERROR) << "Failed to create the events handler for device: "
                  << client.device_data->iio_device_id;
      return;
    }

    events_handlers_.emplace(client.device_data->iio_device_id,
                             std::move(handler));
  }

  events_handlers_.at(client.device_data->iio_device_id)
      ->AddClient(iio_event_indices, std::move(observer));
}

base::WeakPtr<SensorDeviceImpl> SensorDeviceImpl::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

SensorDeviceImpl::SensorDeviceImpl(
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    libmems::IioContext* context,
    std::unique_ptr<base::Thread> thread)
    : ipc_task_runner_(std::move(ipc_task_runner)),
      context_(std::move(context)),
      sample_thread_(std::move(thread)) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  receiver_set_.set_disconnect_handler(base::BindRepeating(
      &SensorDeviceImpl::OnSensorDeviceDisconnect, GetWeakPtr()));
}

void SensorDeviceImpl::OnSensorDeviceDisconnect() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  mojo::ReceiverId id = receiver_set_.current_receiver();

  LOGF(INFO) << "SensorDevice disconnected. ReceiverId: " << id;
  // Run RemoveClient(id) after removing the client from SamplesHandler.
  StopReadingSamplesOnClient(id,
                             base::BindOnce(&SensorDeviceImpl::RemoveClient,
                                            weak_factory_.GetWeakPtr(), id));
}

void SensorDeviceImpl::RemoveClient(mojo::ReceiverId id) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  clients_.erase(id);
}

void SensorDeviceImpl::StopReadingSamplesOnClient(mojo::ReceiverId id,
                                                  base::OnceClosure callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  auto it = clients_.find(id);
  if (it == clients_.end()) {
    LOGF(ERROR) << "Failed to find clients with id: " << id;
    std::move(callback).Run();
    return;
  }

  ClientData& client = it->second;

  auto it_handler = samples_handlers_.find(client.device_data->iio_device_id);
  if (it_handler != samples_handlers_.end())
    it_handler->second->RemoveClient(&client, std::move(callback));
}

}  // namespace iioservice
