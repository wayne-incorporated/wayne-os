// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EVENTS_STYLUS_EVENTS_IMPL_H_
#define DIAGNOSTICS_CROS_HEALTHD_EVENTS_STYLUS_EVENTS_IMPL_H_

#include <string>

#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote_set.h>

#include "diagnostics/cros_healthd/events/stylus_events.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"

namespace diagnostics {

// Production implementation of the StylusEvents interface.
class StylusEventsImpl final : public StylusEvents,
                               public ash::cros_healthd::mojom::StylusObserver {
 public:
  explicit StylusEventsImpl(Context* context);
  StylusEventsImpl(const StylusEventsImpl&) = delete;
  StylusEventsImpl& operator=(const StylusEventsImpl&) = delete;
  ~StylusEventsImpl() = default;

  // StylusEvents overrides:
  void AddObserver(mojo::PendingRemote<ash::cros_healthd::mojom::EventObserver>
                       observer) override;

  // ash::cros_healthd::mojom::StylusObserver overrides:
  void OnTouch(
      ash::cros_healthd::mojom::StylusTouchEventPtr touch_event) override;
  void OnConnected(ash::cros_healthd::mojom::StylusConnectedEventPtr
                       connected_event) override;

 private:
  void StopMonitor(mojo::RemoteSetElementId id);
  void CleanUp(uint32_t custom_reason, const std::string& description);

  // A cached connected event. This event will be emitted to newly added
  // observers if the monitor process has been running.
  ash::cros_healthd::mojom::StylusEventInfoPtr cached_connected_event_;

  // The observer of stylus events.
  mojo::Receiver<ash::cros_healthd::mojom::StylusObserver> receiver_;

  // This is used to control the monitor process. When there is no observer, we
  // should terminate the monitor to save CPU resource.
  mojo::Remote<ash::cros_healthd::mojom::ProcessControl> process_control_;

  // Each observer in |observers_| will be notified of any stylus event.
  // The RemoteSet manages the lifetime of the endpoints, which are
  // automatically destroyed and removed when the pipe they are bound to is
  // destroyed.
  mojo::RemoteSet<ash::cros_healthd::mojom::EventObserver> observers_;

  // Unowned pointer. Should outlive this instance.
  Context* const context_ = nullptr;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EVENTS_STYLUS_EVENTS_IMPL_H_
