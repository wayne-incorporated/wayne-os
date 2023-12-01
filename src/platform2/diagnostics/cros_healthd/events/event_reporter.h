// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EVENTS_EVENT_REPORTER_H_
#define DIAGNOSTICS_CROS_HEALTHD_EVENTS_EVENT_REPORTER_H_

#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/remote_set.h>

#include "diagnostics/cros_healthd/utils/mojo_service_provider.h"
#include "diagnostics/mojom/public/cros_healthd_event_reporters.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"

namespace diagnostics {

class Context;

// Forwards events from the event reporters.
class EventReporter : public ash::cros_healthd::mojom::AshEventReporter {
 public:
  explicit EventReporter(Context* context);
  EventReporter(EventReporter&) = delete;
  EventReporter& operator=(EventReporter&) = delete;
  virtual ~EventReporter();

  // Adds observer to watch events.
  void AddObserver(
      mojo::PendingRemote<ash::cros_healthd::mojom::EventObserver> observer);

  // AshEventReporter overrides.
  void SendKeyboardDiagnosticEvent(
      ash::diagnostics::mojom::KeyboardDiagnosticEventInfoPtr info) override;

 private:
  // The observer set.
  mojo::RemoteSet<ash::cros_healthd::mojom::EventObserver> observers_;
  // The service provider for the AshEventReporter.
  MojoServiceProvider<ash::cros_healthd::mojom::AshEventReporter> ash_provider_{
      this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EVENTS_EVENT_REPORTER_H_
