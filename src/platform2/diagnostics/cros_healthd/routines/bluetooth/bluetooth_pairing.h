// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_PAIRING_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_PAIRING_H_

#include <memory>
#include <string>
#include <vector>

#include <dbus/object_path.h>
#include <base/memory/weak_ptr.h>
#include <base/values.h>
#include <base/time/tick_clock.h>

#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_base.h"
#include "diagnostics/cros_healthd/routines/diag_routine_with_status.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/dbus_bindings/bluetooth/dbus-proxies.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

constexpr base::TimeDelta kRoutinePairingTimeout = base::Seconds(30);
constexpr char kHealthdBluetoothDiagnosticsTag[] = "<healthd_bt_diag_tag>";

class BluetoothPairingRoutine final : public DiagnosticRoutineWithStatus,
                                      public BluetoothRoutineBase {
 public:
  explicit BluetoothPairingRoutine(Context* context,
                                   const std::string& peripheral_id);
  BluetoothPairingRoutine(const BluetoothPairingRoutine&) = delete;
  BluetoothPairingRoutine& operator=(const BluetoothPairingRoutine&) = delete;
  ~BluetoothPairingRoutine() override;

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

  // Remove the device that cached during scanning or failed to remove before.
  void RemoveCachedDeviceIfNeeded();

  // Observe device related events.
  void OnDeviceAdded(org::bluez::Device1ProxyInterface* device);
  void OnDevicePropertyChanged(org::bluez::Device1ProxyInterface* device,
                               const std::string& property_name);

  // Handle the response of error calling Bluez API.
  void HandleError(brillo::Error* error);

  // Handle the response of setting the alias.
  void HandleDeviceAliasChanged(bool is_success);

  // Routine timeout function.
  void OnTimeoutOccurred();

  // Stop discovery if the routine is stopped at some steps.
  void StopDiscoveryIfNeeded();

  // Set the routine result and stop other callbacks.
  void SetResultAndStop(
      ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum status,
      const std::string& status_message);

  enum TestStep {
    kInitialize = 0,
    kEnsurePoweredOn = 1,
    kCheckCurrentDevices = 2,
    kScanTargetDevice = 3,
    kTagTargetDevice = 4,
    kBasebandConnection = 5,
    kPairTargetDevice = 6,
    kMonitorPairedEvent = 7,
    kResetDeviceTag = 8,
    kRemoveTargetDevice = 9,
    kStopDiscovery = 10,
    kComplete = 11,  // Should be the last one. New step should be added before
                     // it.
  };
  TestStep step_ = TestStep::kInitialize;

  // Peripheral ID of routine's target device.
  const std::string peripheral_id_;
  // The device with certain peripheral ID.
  org::bluez::Device1ProxyInterface* target_device_ = nullptr;
  // Details about the routine's execution. Reported in status updates when
  // requested.
  base::Value::Dict output_dict_;
  // Must be the last class member.
  base::WeakPtrFactory<BluetoothPairingRoutine> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_PAIRING_H_
