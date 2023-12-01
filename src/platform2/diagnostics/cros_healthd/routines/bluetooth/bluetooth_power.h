// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_POWER_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_POWER_H_

#include <string>

#include <base/memory/weak_ptr.h>
#include <base/values.h>

#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_base.h"
#include "diagnostics/cros_healthd/routines/diag_routine_with_status.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/dbus_bindings/bluetooth/dbus-proxies.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

constexpr base::TimeDelta kPowerRoutineTimeout = base::Seconds(5);

// The Bluetooth power routine checks that the Bluetooth adapter's power
// functionality is working correctly by checking the off and on powered status
// in D-Bus level and in HCI level.
class BluetoothPowerRoutine final : public DiagnosticRoutineWithStatus,
                                    public BluetoothRoutineBase {
 public:
  explicit BluetoothPowerRoutine(Context* context);
  BluetoothPowerRoutine(const BluetoothPowerRoutine&) = delete;
  BluetoothPowerRoutine& operator=(const BluetoothPowerRoutine&) = delete;
  ~BluetoothPowerRoutine() override;

  // DiagnosticRoutine overrides:
  void Start() override;
  void Resume() override;
  void Cancel() override;
  void PopulateStatusUpdate(ash::cros_healthd::mojom::RoutineUpdate* response,
                            bool include_output) override;

 private:
  void RunNextStep();

  // Handle the response of setting the adapter power.
  void HandleAdapterPoweredChanged(bool is_success);

  // Observe adapter property changed events to check the powered property of
  // adapter in D-Bus level.
  void OnAdapterPropertyChanged(org::bluez::Adapter1ProxyInterface* adapter,
                                const std::string& property_name);

  // Handle the response of hciconfig and check the powered property of adapter
  // in HCI level.
  void HandleHciConfigResponse(
      ash::cros_healthd::mojom::ExecutedProcessResultPtr result);

  // Check the powered property of adapter in D-Bus and HCI level.
  void VerifyAdapterPowered(bool hci_powered);

  // Routine timeout function.
  void OnTimeoutOccurred();

  // Set the routine result and stop other callbacks.
  void SetResultAndStop(
      ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum status,
      const std::string& status_message);

  enum TestStep {
    kInitialize = 0,
    kCheckPoweredStatusOff = 1,
    kCheckPoweredStatusOn = 2,
    kComplete = 3,  // Should be the last one. New step should be added before
                    // it.
  };
  TestStep step_ = TestStep::kInitialize;

  // Details about the routine's execution. Reported in status updates when
  // requested.
  base::Value::Dict output_dict_;
  // Must be the last class member.
  base::WeakPtrFactory<BluetoothPowerRoutine> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_POWER_H_
