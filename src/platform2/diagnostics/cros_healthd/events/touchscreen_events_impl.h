// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EVENTS_TOUCHSCREEN_EVENTS_IMPL_H_
#define DIAGNOSTICS_CROS_HEALTHD_EVENTS_TOUCHSCREEN_EVENTS_IMPL_H_

#include <string>

#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote_set.h>

#include "diagnostics/cros_healthd/events/touchscreen_events.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"

namespace diagnostics {

// Production implementation of the TouchscreenEvents interface.
class TouchscreenEventsImpl final
    : public TouchscreenEvents,
      public ash::cros_healthd::mojom::TouchscreenObserver {
 public:
  explicit TouchscreenEventsImpl(Context* context);
  TouchscreenEventsImpl(const TouchscreenEventsImpl&) = delete;
  TouchscreenEventsImpl& operator=(const TouchscreenEventsImpl&) = delete;
  ~TouchscreenEventsImpl() = default;

  // TouchscreenEvents overrides:
  void AddObserver(mojo::PendingRemote<ash::cros_healthd::mojom::EventObserver>
                       observer) override;

  // ash::cros_healthd::mojom::TouchscreenObserver overrides:
  void OnTouch(
      ash::cros_healthd::mojom::TouchscreenTouchEventPtr touch_event) override;
  void OnConnected(ash::cros_healthd::mojom::TouchscreenConnectedEventPtr
                       connected_event) override;

 private:
  void StopMonitor(mojo::RemoteSetElementId id);
  void CleanUp(uint32_t custom_reason, const std::string& description);

  // A cached connected event. This event will be emitted to newly added
  // observers if the monitor process has been running.
  ash::cros_healthd::mojom::TouchscreenEventInfoPtr cached_connected_event_;

  // The observer of touchscreen events.
  mojo::Receiver<ash::cros_healthd::mojom::TouchscreenObserver> receiver_;

  // This is used to control the monitor process. When there is no observer, we
  // should terminate the monitor to save CPU resource.
  mojo::Remote<ash::cros_healthd::mojom::ProcessControl> process_control_;

  // Each observer in |observers_| will be notified of any touchscreen event.
  // The RemoteSet manages the lifetime of the endpoints, which are
  // automatically destroyed and removed when the pipe they are bound to is
  // destroyed.
  mojo::RemoteSet<ash::cros_healthd::mojom::EventObserver> observers_;

  // Unowned pointer. Should outlive this instance.
  Context* const context_ = nullptr;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EVENTS_TOUCHSCREEN_EVENTS_IMPL_H_
