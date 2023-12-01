// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EVENTS_TOUCHPAD_EVENTS_IMPL_H_
#define DIAGNOSTICS_CROS_HEALTHD_EVENTS_TOUCHPAD_EVENTS_IMPL_H_

#include <string>

#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote_set.h>

#include "diagnostics/cros_healthd/events/touchpad_events.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"

namespace diagnostics {

// Production implementation of the TouchpadEvents interface.
class TouchpadEventsImpl final
    : public TouchpadEvents,
      public ash::cros_healthd::mojom::TouchpadObserver {
 public:
  explicit TouchpadEventsImpl(Context* context);
  TouchpadEventsImpl(const TouchpadEventsImpl&) = delete;
  TouchpadEventsImpl& operator=(const TouchpadEventsImpl&) = delete;
  ~TouchpadEventsImpl() = default;

  // TouchpadEvents overrides:
  void AddObserver(mojo::PendingRemote<ash::cros_healthd::mojom::EventObserver>
                       observer) override;

  // ash::cros_healthd::mojom::TouchpadObserver overrides:
  void OnButton(
      ash::cros_healthd::mojom::TouchpadButtonEventPtr button_event) override;
  void OnTouch(
      ash::cros_healthd::mojom::TouchpadTouchEventPtr touch_event) override;
  void OnConnected(ash::cros_healthd::mojom::TouchpadConnectedEventPtr
                       connected_event) override;

 private:
  void StopMonitor(mojo::RemoteSetElementId id);
  void CleanUp(uint32_t custom_reason, const std::string& description);

  // A cached connected event. This event will be emitted to newly added
  // observers if the monitor process has been running.
  ash::cros_healthd::mojom::TouchpadEventInfoPtr cached_connected_event_;

  // The observer of touchpad events.
  mojo::Receiver<ash::cros_healthd::mojom::TouchpadObserver> receiver_;

  // This is used to control the monitor process. When there is no observer, we
  // should terminate the monitor to save CPU resource.
  mojo::Remote<ash::cros_healthd::mojom::ProcessControl> process_control_;

  // Each observer in |observers_| will be notified of any touchpad event. The
  // RemoteSet manages the lifetime of the endpoints, which are automatically
  // destroyed and removed when the pipe they are bound to is destroyed.
  mojo::RemoteSet<ash::cros_healthd::mojom::EventObserver> observers_;

  // Unowned pointer. Should outlive this instance.
  Context* const context_ = nullptr;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EVENTS_TOUCHPAD_EVENTS_IMPL_H_
