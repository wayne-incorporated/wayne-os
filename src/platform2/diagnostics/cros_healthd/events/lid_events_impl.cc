// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/events/lid_events_impl.h"

#include <string>
#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <power_manager/dbus-proxies.h>

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

// Handles the result of an attempt to connect to a D-Bus signal.
void HandleSignalConnected(const std::string& interface,
                           const std::string& signal,
                           bool success) {
  if (!success) {
    LOG(ERROR) << "Failed to connect to signal " << interface << "." << signal;
    return;
  }
  VLOG(2) << "Successfully connected to D-Bus signal " << interface << "."
          << signal;
}

}  // namespace

namespace diagnostics {
LidEventsImpl::LidEventsImpl(Context* context)
    : context_(context), weak_ptr_factory_(this) {
  DCHECK(context_);

  context_->power_manager_proxy()->RegisterLidClosedSignalHandler(
      base::BindRepeating(&LidEventsImpl::OnLidClosedSignal,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&HandleSignalConnected));
  context_->power_manager_proxy()->RegisterLidOpenedSignalHandler(
      base::BindRepeating(&LidEventsImpl::OnLidOpenedSignal,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&HandleSignalConnected));
}

void LidEventsImpl::AddObserver(
    mojo::PendingRemote<mojom::EventObserver> observer) {
  observers_.Add(std::move(observer));
}

void LidEventsImpl::OnLidClosedSignal() {
  mojom::LidEventInfo info;
  info.state = mojom::LidEventInfo::State::kClosed;

  for (auto& observer : observers_)
    observer->OnEvent(mojom::EventInfo::NewLidEventInfo(info.Clone()));
}

void LidEventsImpl::OnLidOpenedSignal() {
  mojom::LidEventInfo info;
  info.state = mojom::LidEventInfo::State::kOpened;

  for (auto& observer : observers_)
    observer->OnEvent(mojom::EventInfo::NewLidEventInfo(info.Clone()));
}

}  // namespace diagnostics
