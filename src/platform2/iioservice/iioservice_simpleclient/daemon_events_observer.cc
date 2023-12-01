// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/iioservice_simpleclient/daemon_events_observer.h"

#include <utility>

#include <base/functional/bind.h>

#include "iioservice/iioservice_simpleclient/events_observer.h"

namespace iioservice {

DaemonEventsObserver::DaemonEventsObserver(int device_id,
                                           cros::mojom::DeviceType device_type,
                                           std::vector<int> event_indices,
                                           int events)
    : device_id_(device_id),
      device_type_(device_type),
      event_indices_(std::move(event_indices)),
      events_(events),
      weak_ptr_factory_(this) {}

DaemonEventsObserver::~DaemonEventsObserver() = default;

void DaemonEventsObserver::SetSensorClient() {
  sensor_client_ = EventsObserver::Create(
      base::SingleThreadTaskRunner::GetCurrentDefault(), device_id_,
      device_type_, std::move(event_indices_), events_,
      base::BindOnce(&DaemonEventsObserver::OnMojoDisconnect,
                     weak_ptr_factory_.GetWeakPtr()));
}

}  // namespace iioservice
