// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/daemon/events_handler.h"

#include <optional>
#include <utility>

#include <base/containers/contains.h>
#include <base/functional/bind.h>

#include "iioservice/daemon/common_types.h"
#include "iioservice/include/common.h"

namespace iioservice {

namespace {

cros::mojom::IioEventPtr ExtractIioEvent(iio_event_data event) {
  cros::mojom::IioEvent iio_event;
  uint64_t mask = event.id;

  return cros::mojom::IioEvent::New(
      ConvertChanType(
          static_cast<iio_chan_type>(IIO_EVENT_CODE_EXTRACT_CHAN_TYPE(mask))),
      ConvertEventType(
          static_cast<iio_event_type>(IIO_EVENT_CODE_EXTRACT_TYPE(mask))),
      ConvertDirection(
          static_cast<iio_event_direction>(IIO_EVENT_CODE_EXTRACT_DIR(mask))),
      IIO_EVENT_CODE_EXTRACT_CHAN(mask), event.timestamp);
}

}  // namespace

// static
void EventsHandler::EventsHandlerDeleter(EventsHandler* handler) {
  if (handler == nullptr)
    return;

  if (!handler->event_task_runner_->BelongsToCurrentThread()) {
    handler->event_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&EventsHandler::EventsHandlerDeleter, handler));
    return;
  }

  delete handler;
}

// static
EventsHandler::ScopedEventsHandler EventsHandler::Create(
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> event_task_runner,
    libmems::IioDevice* iio_device) {
  ScopedEventsHandler handler(nullptr, EventsHandlerDeleter);

  iio_device->EnableAllEvents();

  handler.reset(new EventsHandler(std::move(ipc_task_runner),
                                  std::move(event_task_runner), iio_device));
  return handler;
}

EventsHandler::~EventsHandler() {
  DCHECK(event_task_runner_->RunsTasksInCurrentSequence());
}

void EventsHandler::ResetWithReason(
    cros::mojom::SensorDeviceDisconnectReason reason, std::string description) {
  event_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&EventsHandler::ResetWithReasonOnThread,
                     weak_factory_.GetWeakPtr(), reason, description));
}

void EventsHandler::AddClient(
    const std::vector<int32_t>& iio_event_indices,
    mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver>
        events_observer) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(!iio_event_indices.empty());

  event_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&EventsHandler::AddClientOnThread,
                                weak_factory_.GetWeakPtr(), iio_event_indices,
                                std::move(events_observer)));
}

EventsHandler::EventsHandler(
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> event_task_runner,
    libmems::IioDevice* iio_device)
    : ipc_task_runner_(std::move(ipc_task_runner)),
      event_task_runner_(std::move(event_task_runner)),
      iio_device_(iio_device) {
  events_observers_.set_disconnect_handler(base::BindRepeating(
      &EventsHandler::OnEventsObserverDisconnect, weak_factory_.GetWeakPtr()));
}

void EventsHandler::ResetWithReasonOnThread(
    cros::mojom::SensorDeviceDisconnectReason reason, std::string description) {
  DCHECK(event_task_runner_->RunsTasksInCurrentSequence());

  // TODO(crbug/1414799): Reset with reason when mojo::RemoteSet supports it.
  events_observers_.Clear();
  enabled_indices_.clear();

  StopEventWatcherOnThread();
}

void EventsHandler::AddClientOnThread(
    const std::vector<int32_t>& iio_event_indices,
    mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver>
        events_observer) {
  DCHECK(event_task_runner_->RunsTasksInCurrentSequence());

  enabled_indices_[events_observers_.Add(std::move(events_observer))] =
      iio_event_indices;

  if (!watcher_.get())
    SetEventWatcherOnThread();
}

void EventsHandler::OnEventsObserverDisconnect(mojo::RemoteSetElementId id) {
  DCHECK(event_task_runner_->RunsTasksInCurrentSequence());

  LOGF(ERROR) << "EventsObserver disconnected. RemoteSetElementId: " << id;

  enabled_indices_.erase(id);
  if (enabled_indices_.empty())
    StopEventWatcherOnThread();
}

void EventsHandler::SetEventWatcherOnThread() {
  DCHECK(event_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(!watcher_.get());

  auto fd = iio_device_->GetEventFd();
  if (!fd.has_value()) {
    LOGF(ERROR) << "Failed to get fd";
    for (auto& observer : events_observers_)
      observer->OnErrorOccurred(cros::mojom::ObserverErrorType::GET_FD_FAILED);

    return;
  }

  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      fd.value(),
      base::BindRepeating(&EventsHandler::OnEventAvailableWithoutBlocking,
                          weak_factory_.GetWeakPtr()));
}

void EventsHandler::StopEventWatcherOnThread() {
  DCHECK(event_task_runner_->RunsTasksInCurrentSequence());

  watcher_.reset();
}

void EventsHandler::OnEventAvailableWithoutBlocking() {
  DCHECK(event_task_runner_->RunsTasksInCurrentSequence());

  auto event = iio_device_->ReadEvent();
  if (!event) {
    for (auto& observer : events_observers_)
      observer->OnErrorOccurred(cros::mojom::ObserverErrorType::READ_FAILED);

    return;
  }

  cros::mojom::IioEventPtr iio_event = ExtractIioEvent(event.value());
  std::optional<int32_t> chn_index;
  for (int32_t i = 0, size = iio_device_->GetAllEvents().size(); i < size;
       ++i) {
    if (iio_device_->GetEvent(i)->MatchMask(event.value().id)) {
      chn_index = i;
      break;
    }
  }
  if (!chn_index.has_value()) {
    LOGF(ERROR) << "No existing events match the mask: " << event.value().id;
    return;
  }

  for (auto& [id, indices] : enabled_indices_) {
    if (!base::Contains(indices, chn_index.value()))
      continue;

    events_observers_.Get(id)->OnEventUpdated(iio_event.Clone());
  }
}

}  // namespace iioservice
