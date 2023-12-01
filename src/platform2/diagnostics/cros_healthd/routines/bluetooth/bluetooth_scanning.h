// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_SCANNING_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_SCANNING_H_

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <dbus/object_path.h>
#include <base/memory/weak_ptr.h>
#include <base/values.h>

#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_base.h"
#include "diagnostics/cros_healthd/routines/diag_routine_with_status.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/dbus_bindings/bluetooth/dbus-proxies.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

constexpr base::TimeDelta kDefaultBluetoothScanningRuntime = base::Seconds(5);

struct ScannedPeripheralDevice {
  std::string peripheral_id;
  std::optional<std::string> name;
  std::vector<int16_t> rssi_history;
  std::optional<uint32_t> bluetooth_class;
  std::vector<std::string> uuids;
};

class BluetoothScanningRoutine final : public DiagnosticRoutineWithStatus,
                                       public BluetoothRoutineBase {
 public:
  explicit BluetoothScanningRoutine(
      Context* context, const std::optional<base::TimeDelta>& exec_duration);
  BluetoothScanningRoutine(const BluetoothScanningRoutine&) = delete;
  BluetoothScanningRoutine& operator=(const BluetoothScanningRoutine&) = delete;
  ~BluetoothScanningRoutine() override;

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

  // Handle the response of error starting/stopping adapter discovery mode.
  void HandleAdapterDiscoveryError(brillo::Error* error);

  // Observe device added and device property changed events to collect RSSI.
  void OnDeviceAdded(org::bluez::Device1ProxyInterface* device);
  void OnDevicePropertyChanged(org::bluez::Device1ProxyInterface* device,
                               const std::string& property_name);

  // Routine timeout function.
  void OnTimeoutOccurred();

  // Set the routine result and stop other callbacks.
  void SetResultAndStop(
      ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum status,
      const std::string& status_message);

  enum TestStep {
    kInitialize = 0,
    kEnsurePoweredOn = 1,
    kStartDiscovery = 2,
    kScanning = 3,
    kStopDiscovery = 4,
    kComplete = 5,  // Should be the last one. New step should be added before
                    // it.
  };
  TestStep step_ = TestStep::kInitialize;

  // Routine execution time.
  const base::TimeDelta exec_duration_;
  // Data of the scanned peripheral devices.
  std::map<dbus::ObjectPath, ScannedPeripheralDevice> scanned_devices_;
  // Must be the last class member.
  base::WeakPtrFactory<BluetoothScanningRoutine> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_SCANNING_H_
