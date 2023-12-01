// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/events/touchscreen_events_impl.h"

#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

}  // namespace

namespace diagnostics {

TouchscreenEventsImpl::TouchscreenEventsImpl(Context* context)
    : receiver_(this), context_(context) {
  DCHECK(context_);

  observers_.set_disconnect_handler(base::BindRepeating(
      &TouchscreenEventsImpl::StopMonitor, base::Unretained(this)));
}

void TouchscreenEventsImpl::AddObserver(
    mojo::PendingRemote<mojom::EventObserver> observer) {
  auto element_id = observers_.Add(std::move(observer));
  if (observers_.size() == 1) {
    context_->executor()->MonitorTouchscreen(
        receiver_.BindNewPipeAndPassRemote(),
        process_control_.BindNewPipeAndPassReceiver());
    receiver_.set_disconnect_with_reason_handler(base::BindOnce(
        &TouchscreenEventsImpl::CleanUp, base::Unretained(this)));
  } else {
    if (cached_connected_event_) {
      observers_.Get(element_id)
          ->OnEvent(mojom::EventInfo::NewTouchscreenEventInfo(
              cached_connected_event_.Clone()));
    }
  }
}

void TouchscreenEventsImpl::OnTouch(
    mojom::TouchscreenTouchEventPtr touch_event) {
  auto info = mojom::TouchscreenEventInfo::NewTouchEvent(touch_event.Clone());
  for (auto& observer : observers_)
    observer->OnEvent(mojom::EventInfo::NewTouchscreenEventInfo(info.Clone()));
}

void TouchscreenEventsImpl::OnConnected(
    mojom::TouchscreenConnectedEventPtr connected_event) {
  cached_connected_event_ =
      mojom::TouchscreenEventInfo::NewConnectedEvent(connected_event.Clone());
  for (auto& observer : observers_)
    observer->OnEvent(mojom::EventInfo::NewTouchscreenEventInfo(
        cached_connected_event_.Clone()));
}

void TouchscreenEventsImpl::StopMonitor(mojo::RemoteSetElementId id) {
  if (observers_.empty()) {
    process_control_.reset();
    receiver_.reset();
  }
}

void TouchscreenEventsImpl::CleanUp(uint32_t custom_reason,
                                    const std::string& description) {
  observers_.ClearWithReason(custom_reason, description);
  cached_connected_event_.reset();
}

}  // namespace diagnostics
