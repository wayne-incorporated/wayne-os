// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/events/audio_jack_events_impl.h"

#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

}  // namespace

namespace diagnostics {

AudioJackEventsImpl::AudioJackEventsImpl(Context* context)
    : receiver_(this), context_(context) {
  DCHECK(context_);

  observers_.set_disconnect_handler(base::BindRepeating(
      &AudioJackEventsImpl::StopMonitor, base::Unretained(this)));
}

void AudioJackEventsImpl::AddObserver(
    mojo::PendingRemote<mojom::EventObserver> observer) {
  observers_.Add(std::move(observer));
  StartMonitor();
}

void AudioJackEventsImpl::OnAdd(
    mojom::AudioJackEventInfo::DeviceType device_type) {
  mojom::AudioJackEventInfo info;
  info.state = mojom::AudioJackEventInfo::State::kAdd;
  info.device_type = device_type;

  for (auto& observer : observers_)
    observer->OnEvent(mojom::EventInfo::NewAudioJackEventInfo(info.Clone()));
}

void AudioJackEventsImpl::OnRemove(
    mojom::AudioJackEventInfo::DeviceType device_type) {
  mojom::AudioJackEventInfo info;
  info.state = mojom::AudioJackEventInfo::State::kRemove;
  info.device_type = device_type;

  for (auto& observer : observers_)
    observer->OnEvent(mojom::EventInfo::NewAudioJackEventInfo(info.Clone()));
}

void AudioJackEventsImpl::StartMonitor() {
  if (observers_.size() == 1) {
    context_->executor()->MonitorAudioJack(
        receiver_.BindNewPipeAndPassRemote(),
        process_control_.BindNewPipeAndPassReceiver());
    receiver_.set_disconnect_with_reason_handler(
        base::BindOnce(&AudioJackEventsImpl::CleanUp, base::Unretained(this)));
  }
}

void AudioJackEventsImpl::StopMonitor(mojo::RemoteSetElementId id) {
  if (observers_.empty()) {
    process_control_.reset();
    receiver_.reset();
  }
}

void AudioJackEventsImpl::CleanUp(uint32_t custom_reason,
                                  const std::string& description) {
  observers_.ClearWithReason(custom_reason, description);
}

}  // namespace diagnostics
