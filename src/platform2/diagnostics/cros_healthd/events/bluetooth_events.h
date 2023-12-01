// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EVENTS_BLUETOOTH_EVENTS_H_
#define DIAGNOSTICS_CROS_HEALTHD_EVENTS_BLUETOOTH_EVENTS_H_

#include <mojo/public/cpp/bindings/pending_remote.h>

#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"

namespace diagnostics {

// Interface that allows clients to subscribe to Bluetooth-related events.
class BluetoothEvents {
 public:
  virtual ~BluetoothEvents() = default;

  // Adds a new observer to be notified when Bluetooth-related events occur.
  virtual void AddObserver(
      mojo::PendingRemote<ash::cros_healthd::mojom::EventObserver>
          observer) = 0;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EVENTS_BLUETOOTH_EVENTS_H_
