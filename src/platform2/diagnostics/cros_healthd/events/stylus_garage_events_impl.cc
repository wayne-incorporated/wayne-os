// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/events/stylus_garage_events_impl.h"

#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

}  // namespace

namespace diagnostics {

StylusGarageEventsImpl::StylusGarageEventsImpl(Context* context)
    : receiver_(this), context_(context) {
  DCHECK(context_);

  observers_.set_disconnect_handler(base::BindRepeating(
      &StylusGarageEventsImpl::StopMonitor, base::Unretained(this)));
}

void StylusGarageEventsImpl::AddObserver(
    mojo::PendingRemote<mojom::EventObserver> observer) {
  observers_.Add(std::move(observer));
  StartMonitor();
}

void StylusGarageEventsImpl::OnInsert() {
  mojom::StylusGarageEventInfo info;
  info.state = mojom::StylusGarageEventInfo::State::kInserted;

  for (auto& observer : observers_)
    observer->OnEvent(mojom::EventInfo::NewStylusGarageEventInfo(info.Clone()));
}

void StylusGarageEventsImpl::OnRemove() {
  mojom::StylusGarageEventInfo info;
  info.state = mojom::StylusGarageEventInfo::State::kRemoved;

  for (auto& observer : observers_)
    observer->OnEvent(mojom::EventInfo::NewStylusGarageEventInfo(info.Clone()));
}

void StylusGarageEventsImpl::StartMonitor() {
  if (observers_.size() == 1) {
    context_->executor()->MonitorStylusGarage(
        receiver_.BindNewPipeAndPassRemote(),
        process_control_.BindNewPipeAndPassReceiver());
    receiver_.set_disconnect_with_reason_handler(base::BindOnce(
        &StylusGarageEventsImpl::CleanUp, base::Unretained(this)));
  }
}

void StylusGarageEventsImpl::StopMonitor(mojo::RemoteSetElementId id) {
  if (observers_.empty()) {
    process_control_.reset();
    receiver_.reset();
  }
}

void StylusGarageEventsImpl::CleanUp(uint32_t custom_reason,
                                     const std::string& description) {
  observers_.ClearWithReason(custom_reason, description);
}

}  // namespace diagnostics
