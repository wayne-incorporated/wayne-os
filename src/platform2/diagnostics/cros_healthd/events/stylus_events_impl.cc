// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/events/stylus_events_impl.h"

#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

}  // namespace

namespace diagnostics {

StylusEventsImpl::StylusEventsImpl(Context* context)
    : receiver_(this), context_(context) {
  DCHECK(context_);

  observers_.set_disconnect_handler(base::BindRepeating(
      &StylusEventsImpl::StopMonitor, base::Unretained(this)));
}

void StylusEventsImpl::AddObserver(
    mojo::PendingRemote<mojom::EventObserver> observer) {
  auto element_id = observers_.Add(std::move(observer));
  if (observers_.size() == 1) {
    context_->executor()->MonitorStylus(
        receiver_.BindNewPipeAndPassRemote(),
        process_control_.BindNewPipeAndPassReceiver());
    receiver_.set_disconnect_with_reason_handler(
        base::BindOnce(&StylusEventsImpl::CleanUp, base::Unretained(this)));
  } else {
    if (cached_connected_event_) {
      observers_.Get(element_id)
          ->OnEvent(mojom::EventInfo::NewStylusEventInfo(
              cached_connected_event_.Clone()));
    }
  }
}

void StylusEventsImpl::OnTouch(mojom::StylusTouchEventPtr touch_event) {
  auto info = mojom::StylusEventInfo::NewTouchEvent(touch_event.Clone());
  for (auto& observer : observers_)
    observer->OnEvent(mojom::EventInfo::NewStylusEventInfo(info.Clone()));
}

void StylusEventsImpl::OnConnected(
    mojom::StylusConnectedEventPtr connected_event) {
  cached_connected_event_ =
      mojom::StylusEventInfo::NewConnectedEvent(connected_event.Clone());
  for (auto& observer : observers_)
    observer->OnEvent(
        mojom::EventInfo::NewStylusEventInfo(cached_connected_event_.Clone()));
}

void StylusEventsImpl::StopMonitor(mojo::RemoteSetElementId id) {
  if (observers_.empty()) {
    process_control_.reset();
    receiver_.reset();
  }
}

void StylusEventsImpl::CleanUp(uint32_t custom_reason,
                               const std::string& description) {
  observers_.ClearWithReason(custom_reason, description);
  cached_connected_event_.reset();
}

}  // namespace diagnostics
