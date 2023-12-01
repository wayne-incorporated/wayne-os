// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_BASE_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_BASE_H_

#include <optional>
#include <string>
#include <vector>

#include <base/callback_list.h>
#include <base/time/tick_clock.h>

#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/dbus_bindings/bluetooth/dbus-proxies.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

// This class abstracts common interfaces for all Bluetooth related routines.
class BluetoothRoutineBase {
 public:
  explicit BluetoothRoutineBase(Context* context);
  BluetoothRoutineBase(const BluetoothRoutineBase&) = delete;
  BluetoothRoutineBase& operator=(const BluetoothRoutineBase&) = delete;
  ~BluetoothRoutineBase();

  // Getter of the main Bluetooth adapter.
  org::bluez::Adapter1ProxyInterface* GetAdapter() const;

  // Ensure the adapter powered state is |powered|.
  void EnsureAdapterPoweredState(bool powered,
                                 base::OnceCallback<void(bool)> on_finish);

  // Run the pre-check for the Bluetooth routine. Bluetooth routines should not
  // be run when the adapter is already in discovery mode.
  void RunPreCheck(
      base::OnceClosure on_passed,
      base::OnceCallback<
          void(ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum status,
               const std::string& error_message)> on_failed);

  // Set the adapter powered state back to |initial_powered_state_|.
  void ResetPoweredState();

 protected:
  // Unowned pointer that should outlive this instance.
  Context* const context_;
  // Routine start time, used to calculate the progress percentage and timeout.
  base::TimeTicks start_ticks_;
  // The callback will be unregistered when the subscription is destructured.
  std::vector<base::CallbackListSubscription> event_subscriptions_;

 private:
  // The adapters from Bluetooth proxy.
  std::vector<org::bluez::Adapter1ProxyInterface*> adapters_;
  // The initial powered state of the adapter.
  std::optional<bool> initial_powered_state_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_BASE_H_
