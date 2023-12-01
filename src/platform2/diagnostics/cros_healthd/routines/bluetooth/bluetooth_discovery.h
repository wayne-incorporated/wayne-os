// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_DISCOVERY_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_DISCOVERY_H_

#include <memory>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/values.h>

#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_base.h"
#include "diagnostics/cros_healthd/routines/diag_routine_with_status.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/dbus_bindings/bluetooth/dbus-proxies.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

constexpr base::TimeDelta kRoutineDiscoveryTimeout = base::Seconds(5);

// The Bluetooth discovery routine checks that the Bluetooth adapter can start
// and stop discovery mode correctly by checking the on and off discovering
// status in D-Bus level and in HCI level.
class BluetoothDiscoveryRoutine final : public DiagnosticRoutineWithStatus,
                                        public BluetoothRoutineBase {
 public:
  explicit BluetoothDiscoveryRoutine(Context* context);
  BluetoothDiscoveryRoutine(const BluetoothDiscoveryRoutine&) = delete;
  BluetoothDiscoveryRoutine& operator=(const BluetoothDiscoveryRoutine&) =
      delete;
  ~BluetoothDiscoveryRoutine() override;

  // DiagnosticRoutine overrides:
  void Start() override;
  void Resume() override;
  void Cancel() override;
  void PopulateStatusUpdate(ash::cros_healthd::mojom::RoutineUpdate* response,
                            bool include_output) override;

 private:
  void RunNextStep();

  // Handle the response of powering on the adapter.
  void HandleAdapterPoweredOn(bool is_success);

  // Handle the response of successfully starting/stopping adapter discovery
  // mode.
  void HandleAdapterDiscoverySuccess();

  // Handle the response of error starting/stopping adapter discovery mode.
  void HandleAdapterDiscoveryError(brillo::Error* error);

  // Observe adapter property changed events to check the discovering property
  // of adapter in D-Bus level.
  void OnAdapterPropertyChanged(org::bluez::Adapter1ProxyInterface* adapter,
                                const std::string& property_name);

  // Handle the response of hciconfig and check the discovering property of
  // adapter in HCI level.
  void HandleHciConfigResponse(
      bool dbus_discovering,
      ash::cros_healthd::mojom::ExecutedProcessResultPtr result);

  // Verify the discovering property of adapter and store the result.
  void VerifyAdapterDiscovering(bool dbus_discovering, bool hci_discovering);

  // Routine timeout function.
  void OnTimeoutOccurred();

  // Set the routine result and stop other callbacks.
  void SetResultAndStop(
      ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum status,
      const std::string& status_message);

  enum TestStep {
    kInitialize = 0,
    kEnsurePoweredOn = 1,
    kCheckDiscoveringStatusOn = 2,
    kCheckDiscoveringStatusOff = 3,
    kComplete = 4,  // Should be the last one. New step should be added before
                    // it.
  };
  TestStep step_ = TestStep::kInitialize;

  // Details about the routine's execution. Reported in status updates when
  // requested.
  base::Value::Dict output_dict_;
  // Must be the last class member.
  base::WeakPtrFactory<BluetoothDiscoveryRoutine> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_DISCOVERY_H_
