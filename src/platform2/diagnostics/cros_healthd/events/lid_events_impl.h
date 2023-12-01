// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EVENTS_LID_EVENTS_IMPL_H_
#define DIAGNOSTICS_CROS_HEALTHD_EVENTS_LID_EVENTS_IMPL_H_

#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/remote_set.h>

#include "diagnostics/cros_healthd/events/lid_events.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"

namespace diagnostics {

// Production implementation of the LidEvents interface.
class LidEventsImpl final : public LidEvents {
 public:
  explicit LidEventsImpl(Context* context);
  LidEventsImpl(const LidEventsImpl&) = delete;
  LidEventsImpl& operator=(const LidEventsImpl&) = delete;
  ~LidEventsImpl() = default;

  // LidEvents overrides:
  void AddObserver(mojo::PendingRemote<ash::cros_healthd::mojom::EventObserver>
                       observer) override;

 private:
  void OnLidClosedSignal();
  void OnLidOpenedSignal();

  // Each observer in |observers_| will be notified of any lid event in the
  // ash::cros_healthd::mojom::EventObserver interface. The RemoteSet manages
  // the lifetime of the endpoints, which are automatically destroyed and
  // removed when the pipe they are bound to is destroyed.
  mojo::RemoteSet<ash::cros_healthd::mojom::EventObserver> observers_;

  // Unowned pointer. Should outlive this instance.
  Context* const context_ = nullptr;

  base::WeakPtrFactory<LidEventsImpl> weak_ptr_factory_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EVENTS_LID_EVENTS_IMPL_H_
