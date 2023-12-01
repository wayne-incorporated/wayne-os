// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/iioservice_simpleclient/events_observer.h"

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
EventsObserver::ScopedEventsObserver EventsObserver::Create(
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    int device_id,
    cros::mojom::DeviceType device_type,
    std::vector<int> event_indices,
    int events,
    QuitCallback quit_callback) {
  ScopedEventsObserver observer(
      new EventsObserver(ipc_task_runner, device_id, device_type,
                         std::move(event_indices), events,
                         std::move(quit_callback)),
      SensorClientDeleter);

  return observer;
}

void EventsObserver::OnEventUpdated(cros::mojom::IioEventPtr event) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  // TODO(chenghaoyang): verify event is within the enabled channels.
  LOGF(INFO) << "ChanType: " << event->chan_type
             << ", EventType: " << event->event_type
             << ", Direction: " << event->direction
             << ", channel: " << event->channel
             << ", timestamp: " << event->timestamp;

  AddTimestamp(event->timestamp);

  AddSuccessRead();
}

void EventsObserver::OnErrorOccurred(cros::mojom::ObserverErrorType type) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  // Don't Change: Used as a check sentence in the tast test.
  LOGF(ERROR) << "OnErrorOccurred: " << type;
  Reset();
}

EventsObserver::EventsObserver(
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    int device_id,
    cros::mojom::DeviceType device_type,
    std::vector<int> event_indices,
    int events,
    QuitCallback quit_callback)
    : Observer(std::move(ipc_task_runner),
               std::move(quit_callback),
               device_id,
               device_type,
               events),
      event_indices_(std::move(event_indices)),
      receiver_(this) {}

void EventsObserver::Reset() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  sensor_device_remote_.reset();
  receiver_.reset();

  SensorClient::Reset();
}

mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver>
EventsObserver::GetRemote() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  auto remote = receiver_.BindNewPipeAndPassRemote();
  receiver_.set_disconnect_handler(base::BindOnce(
      &EventsObserver::OnObserverDisconnect, weak_factory_.GetWeakPtr()));

  return remote;
}

void EventsObserver::GetSensorDevice() {
  Observer::GetSensorDevice();

  StartReading();
}

void EventsObserver::StartReading() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  sensor_device_remote_->StartReadingEvents(event_indices_, GetRemote());
}

}  // namespace iioservice
