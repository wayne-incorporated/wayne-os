// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_pairing.h"

#include <algorithm>
#include <memory>
#include <numeric>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/hash/hash.h>
#include <base/json/json_writer.h>
#include <base/strings/string_number_conversions.h>
#include <base/logging.h>

#include "diagnostics/base/mojo_utils.h"
#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_constants.h"
#include "diagnostics/cros_healthd/system/bluetooth_event_hub.h"
#include "diagnostics/cros_healthd/system/bluetooth_info_manager.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

base::Value::Dict GetErrorDict(brillo::Error* error) {
  base::Value::Dict out_error;
  if (error) {
    out_error.Set("code", error->GetCode());
    out_error.Set("message", error->GetMessage());
  }
  return out_error;
}

}  // namespace

BluetoothPairingRoutine::BluetoothPairingRoutine(
    Context* context, const std::string& peripheral_id)
    : BluetoothRoutineBase(context), peripheral_id_(peripheral_id) {}

BluetoothPairingRoutine::~BluetoothPairingRoutine() = default;

void BluetoothPairingRoutine::Start() {
  DCHECK_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);

  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning,
               kBluetoothRoutineRunningMessage);
  start_ticks_ = base::TimeTicks::Now();

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&BluetoothPairingRoutine::OnTimeoutOccurred,
                     weak_ptr_factory_.GetWeakPtr()),
      kRoutinePairingTimeout);

  event_subscriptions_.push_back(
      context_->bluetooth_event_hub()->SubscribeDeviceAdded(
          base::BindRepeating(&BluetoothPairingRoutine::OnDeviceAdded,
                              weak_ptr_factory_.GetWeakPtr())));
  event_subscriptions_.push_back(
      context_->bluetooth_event_hub()->SubscribeDevicePropertyChanged(
          base::BindRepeating(&BluetoothPairingRoutine::OnDevicePropertyChanged,
                              weak_ptr_factory_.GetWeakPtr())));

  RunPreCheck(
      /*on_passed=*/base::BindOnce(&BluetoothPairingRoutine::RunNextStep,
                                   weak_ptr_factory_.GetWeakPtr()),
      /*on_failed=*/base::BindOnce(&BluetoothPairingRoutine::SetResultAndStop,
                                   weak_ptr_factory_.GetWeakPtr()));
}

void BluetoothPairingRoutine::Resume() {
  LOG(ERROR) << "Bluetooth pairing routine cannot be resumed";
}

void BluetoothPairingRoutine::Cancel() {
  LOG(ERROR) << "Bluetooth pairing routine cannot be cancelled";
}

void BluetoothPairingRoutine::PopulateStatusUpdate(
    mojom::RoutineUpdate* response, bool include_output) {
  DCHECK(response);
  auto status = GetStatus();

  response->routine_update_union =
      mojom::RoutineUpdateUnion::NewNoninteractiveUpdate(
          mojom::NonInteractiveRoutineUpdate::New(status, GetStatusMessage()));

  if (include_output) {
    std::string json;
    base::JSONWriter::Write(output_dict_, &json);
    response->output =
        CreateReadOnlySharedMemoryRegionMojoHandle(base::StringPiece(json));
  }

  // The routine is failed.
  if (status == mojom::DiagnosticRoutineStatusEnum::kFailed ||
      status == mojom::DiagnosticRoutineStatusEnum::kError) {
    response->progress_percent = 100;
    return;
  }

  // The routine is not started.
  if (status == mojom::DiagnosticRoutineStatusEnum::kReady) {
    response->progress_percent = 0;
    return;
  }

  double step_percent = step_ * 100 / TestStep::kComplete;
  double running_time_ratio =
      (base::TimeTicks::Now() - start_ticks_) / kRoutinePairingTimeout;
  response->progress_percent =
      step_percent + (100 - step_percent) * std::min(1.0, running_time_ratio);
}

void BluetoothPairingRoutine::RunNextStep() {
  step_ = static_cast<TestStep>(static_cast<int>(step_) + 1);

  switch (step_) {
    case TestStep::kInitialize:
      SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                       kBluetoothRoutineUnexpectedFlow);
      break;
    case TestStep::kEnsurePoweredOn:
      EnsureAdapterPoweredState(
          /*powered=*/true,
          base::BindOnce(&BluetoothPairingRoutine::HandleAdapterPoweredOn,
                         weak_ptr_factory_.GetWeakPtr()));
      break;
    case TestStep::kCheckCurrentDevices:
      // We need to make sure that the target device is not cached before the
      // scanning part since we want to subscribe the device added event for it.
      RemoveCachedDeviceIfNeeded();
      break;
    case TestStep::kScanTargetDevice:
      // Scan to find the |target_device_| at this step. We will run the next
      // step in |OnDeviceAdded| once the device is found.
      GetAdapter()->StartDiscoveryAsync(
          base::DoNothing(),
          base::BindOnce(&BluetoothPairingRoutine::HandleError,
                         weak_ptr_factory_.GetWeakPtr()));
      break;
    case TestStep::kTagTargetDevice:
      target_device_->set_alias(
          kHealthdBluetoothDiagnosticsTag,
          base::BindOnce(&BluetoothPairingRoutine::HandleDeviceAliasChanged,
                         weak_ptr_factory_.GetWeakPtr()));
      break;
    case TestStep::kBasebandConnection:
      target_device_->ConnectAsync(
          base::BindOnce(&BluetoothPairingRoutine::RunNextStep,
                         weak_ptr_factory_.GetWeakPtr()),
          base::BindOnce(&BluetoothPairingRoutine::HandleError,
                         weak_ptr_factory_.GetWeakPtr()));
      break;
    case TestStep::kPairTargetDevice:
      if (!target_device_->connected()) {
        SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kFailed,
                         kBluetoothRoutineFailedCreateBasebandConnection);
        return;
      }

      if (target_device_->paired()) {
        // Some peripherals might upgrade security level depending on their
        // configuration, so pairing (or authentication/authorization) may be
        // required after a connection is created. Skip the pairing if the
        // device is paired automatically during connecting.
        RunNextStep();
      } else {
        target_device_->PairAsync(
            base::BindOnce(&BluetoothPairingRoutine::RunNextStep,
                           weak_ptr_factory_.GetWeakPtr()),
            base::BindOnce(&BluetoothPairingRoutine::HandleError,
                           weak_ptr_factory_.GetWeakPtr()));
      }
      break;
    case TestStep::kMonitorPairedEvent:
      // In most cases, the device will be already paired after the Pair
      // function is complete.
      if (target_device_->paired()) {
        RunNextStep();
      }
      // But some devices require one more verification step, e.g., we need to
      // enter corresponding passkey on Bluetooth keyboard to pair. We will run
      // the next step in |OnDevicePropertyChanged| once the device paired
      // status event is received.
      break;
    case TestStep::kResetDeviceTag:
      target_device_->set_alias(
          "", base::BindOnce(&BluetoothPairingRoutine::HandleDeviceAliasChanged,
                             weak_ptr_factory_.GetWeakPtr()));
      break;
    case TestStep::kRemoveTargetDevice:
      GetAdapter()->RemoveDeviceAsync(
          target_device_->GetObjectPath(),
          base::BindOnce(&BluetoothPairingRoutine::RunNextStep,
                         weak_ptr_factory_.GetWeakPtr()),
          base::BindOnce(&BluetoothPairingRoutine::HandleError,
                         weak_ptr_factory_.GetWeakPtr()));
      break;
    case TestStep::kStopDiscovery:
      GetAdapter()->StopDiscoveryAsync(
          base::BindOnce(&BluetoothPairingRoutine::RunNextStep,
                         weak_ptr_factory_.GetWeakPtr()),
          base::BindOnce(&BluetoothPairingRoutine::HandleError,
                         weak_ptr_factory_.GetWeakPtr()));
      break;
    case TestStep::kComplete:
      SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kPassed,
                       kBluetoothRoutinePassedMessage);
      break;
  }
}

void BluetoothPairingRoutine::HandleAdapterPoweredOn(bool is_success) {
  if (!is_success) {
    SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                     kBluetoothRoutineFailedChangePowered);
    return;
  }
  RunNextStep();
}

void BluetoothPairingRoutine::RemoveCachedDeviceIfNeeded() {
  for (const auto& device : context_->bluetooth_info_manager()->GetDevices()) {
    if (!device)
      continue;

    auto device_id = base::NumberToString(base::FastHash(device->address()));
    bool is_target_device = peripheral_id_ == device_id;

    // Clear the testing device that failed to remove before.
    if (device->alias() == kHealthdBluetoothDiagnosticsTag &&
        !is_target_device) {
      GetAdapter()->RemoveDeviceAsync(device->GetObjectPath(),
                                      base::DoNothing(), base::DoNothing());
    }

    if (!is_target_device)
      continue;

    if (device->paired()) {
      SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kFailed,
                       "The target peripheral is already paired.");
      return;
    }

    GetAdapter()->RemoveDeviceAsync(
        device->GetObjectPath(),
        base::BindOnce(&BluetoothPairingRoutine::RunNextStep,
                       weak_ptr_factory_.GetWeakPtr()),
        base::BindOnce(&BluetoothPairingRoutine::HandleError,
                       weak_ptr_factory_.GetWeakPtr()));
    return;
  }
  // Run next step directly if the target device is not found.
  RunNextStep();
}

void BluetoothPairingRoutine::OnDeviceAdded(
    org::bluez::Device1ProxyInterface* device) {
  if (!device || target_device_ || step_ != TestStep::kScanTargetDevice ||
      peripheral_id_ != base::NumberToString(base::FastHash(device->address())))
    return;

  if (device->is_bluetooth_class_valid()) {
    output_dict_.Set("bluetooth_class",
                     base::NumberToString(device->bluetooth_class()));
  }
  if (device->is_uuids_valid()) {
    base::Value::List out_uuids;
    for (const auto& uuid : device->uuids())
      out_uuids.Append(uuid);
    output_dict_.Set("uuids", std::move(out_uuids));
  }

  target_device_ = device;
  RunNextStep();
}

void BluetoothPairingRoutine::OnDevicePropertyChanged(
    org::bluez::Device1ProxyInterface* device,
    const std::string& property_name) {
  if (!device || device != target_device_)
    return;

  if (property_name == device->ClassName()) {
    if (device->is_bluetooth_class_valid()) {
      output_dict_.Set("bluetooth_class",
                       base::NumberToString(device->bluetooth_class()));
    }
  } else if (property_name == device->UUIDsName()) {
    if (device->is_uuids_valid()) {
      base::Value::List out_uuids;
      for (const auto& uuid : device->uuids())
        out_uuids.Append(uuid);
      output_dict_.Set("uuids", std::move(out_uuids));
    }
  } else if (property_name == device->PairedName()) {
    if (step_ == TestStep::kMonitorPairedEvent) {
      if (target_device_->paired()) {
        RunNextStep();
        return;
      }
      SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kFailed,
                       kBluetoothRoutineFailedFinishPairing);
    } else if (step_ == TestStep::kPairTargetDevice) {
      // TODO(b/270523273): Remove paired changed event observation here.
      // The success callback of PairAsync might not be invoked but the device
      // will be actually paired and we will receive paired changed event. Add a
      // workaround to handle this case here.
      if (target_device_->paired()) {
        step_ = TestStep::kMonitorPairedEvent;
        RunNextStep();
        return;
      }
      SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kFailed,
                       kBluetoothRoutineFailedFinishPairing);
    }
  }
}

void BluetoothPairingRoutine::HandleError(brillo::Error* error) {
  switch (step_) {
    case TestStep::kScanTargetDevice:
    case TestStep::kStopDiscovery:
      SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                       kBluetoothRoutineFailedSwitchDiscovery);
      break;
    case TestStep::kCheckCurrentDevices:
    case TestStep::kRemoveTargetDevice:
      SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kFailed,
                       "Bluetooth routine failed to remove target peripheral.");
      break;
    case TestStep::kBasebandConnection:
      output_dict_.Set("connect_error", GetErrorDict(error));
      SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kFailed,
                       kBluetoothRoutineFailedCreateBasebandConnection);
      break;
    case TestStep::kPairTargetDevice:
      output_dict_.Set("pair_error", GetErrorDict(error));
      SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kFailed,
                       kBluetoothRoutineFailedFinishPairing);
      break;
    default:
      SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                       kBluetoothRoutineUnexpectedFlow);
      break;
  }
}

void BluetoothPairingRoutine::HandleDeviceAliasChanged(bool is_success) {
  switch (step_) {
    case TestStep::kTagTargetDevice:
    case TestStep::kResetDeviceTag:
      if (!is_success) {
        SetResultAndStop(
            mojom::DiagnosticRoutineStatusEnum::kFailed,
            "Bluetooth routine failed to set target device's alias.");
        return;
      }
      RunNextStep();
      break;
    default:
      SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                       kBluetoothRoutineUnexpectedFlow);
      break;
  }
}

void BluetoothPairingRoutine::OnTimeoutOccurred() {
  if (step_ == TestStep::kScanTargetDevice) {
    SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kFailed,
                     kBluetoothRoutineFailedFindTargetPeripheral);
    return;
  }
  SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kFailed,
                   kBluetoothRoutineFailedFinishPairing);
}

void BluetoothPairingRoutine::StopDiscoveryIfNeeded() {
  if (step_ < TestStep::kScanTargetDevice || step_ >= TestStep::kStopDiscovery)
    return;

  GetAdapter()->StopDiscoveryAsync(base::DoNothing(), base::DoNothing());
}

void BluetoothPairingRoutine::SetResultAndStop(
    mojom::DiagnosticRoutineStatusEnum status,
    const std::string& status_message) {
  StopDiscoveryIfNeeded();
  // Cancel all pending callbacks.
  weak_ptr_factory_.InvalidateWeakPtrs();
  UpdateStatus(status, status_message);
}

}  // namespace diagnostics
