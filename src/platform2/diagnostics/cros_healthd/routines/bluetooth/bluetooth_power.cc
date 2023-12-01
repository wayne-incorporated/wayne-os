// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_power.h"

#include <algorithm>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>

#include "diagnostics/base/mojo_utils.h"
#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_constants.h"
#include "diagnostics/cros_healthd/system/bluetooth_event_hub.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

}  // namespace

BluetoothPowerRoutine::BluetoothPowerRoutine(Context* context)
    : BluetoothRoutineBase(context) {}

BluetoothPowerRoutine::~BluetoothPowerRoutine() = default;

void BluetoothPowerRoutine::Start() {
  DCHECK_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);

  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning,
               kBluetoothRoutineRunningMessage);
  start_ticks_ = base::TimeTicks::Now();

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&BluetoothPowerRoutine::OnTimeoutOccurred,
                     weak_ptr_factory_.GetWeakPtr()),
      kPowerRoutineTimeout);

  event_subscriptions_.push_back(
      context_->bluetooth_event_hub()->SubscribeAdapterPropertyChanged(
          base::BindRepeating(&BluetoothPowerRoutine::OnAdapterPropertyChanged,
                              weak_ptr_factory_.GetWeakPtr())));

  RunPreCheck(
      /*on_passed=*/base::BindOnce(&BluetoothPowerRoutine::RunNextStep,
                                   weak_ptr_factory_.GetWeakPtr()),
      /*on_failed=*/base::BindOnce(&BluetoothPowerRoutine::SetResultAndStop,
                                   weak_ptr_factory_.GetWeakPtr()));
}

void BluetoothPowerRoutine::Resume() {
  LOG(ERROR) << "Bluetooth power routine cannot be resumed";
}

void BluetoothPowerRoutine::Cancel() {
  LOG(ERROR) << "Bluetooth power routine cannot be cancelled";
}

void BluetoothPowerRoutine::PopulateStatusUpdate(mojom::RoutineUpdate* response,
                                                 bool include_output) {
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
      (base::TimeTicks::Now() - start_ticks_) / kPowerRoutineTimeout;
  response->progress_percent =
      step_percent + (100 - step_percent) * std::min(1.0, running_time_ratio);
}

void BluetoothPowerRoutine::RunNextStep() {
  step_ = static_cast<TestStep>(static_cast<int>(step_) + 1);

  switch (step_) {
    case TestStep::kInitialize:
      SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                       kBluetoothRoutineUnexpectedFlow);
      break;
    case TestStep::kCheckPoweredStatusOff:
      // We can't get the power off event when the power is already off.
      // Create another flow to skip event observation.
      if (!GetAdapter()->powered()) {
        // Verify the powered status in HCI level directly.
        context_->executor()->GetHciDeviceConfig(
            base::BindOnce(&BluetoothPowerRoutine::HandleHciConfigResponse,
                           weak_ptr_factory_.GetWeakPtr()));
        return;
      }
      // Wait for the property changed event in |OnAdapterPropertyChanged|.
      EnsureAdapterPoweredState(
          /*powered=*/false,
          base::BindOnce(&BluetoothPowerRoutine::HandleAdapterPoweredChanged,
                         weak_ptr_factory_.GetWeakPtr()));
      break;
    case TestStep::kCheckPoweredStatusOn:
      // Wait for the property changed event in |OnAdapterPropertyChanged|.
      EnsureAdapterPoweredState(
          /*powered=*/true,
          base::BindOnce(&BluetoothPowerRoutine::HandleAdapterPoweredChanged,
                         weak_ptr_factory_.GetWeakPtr()));
      break;
    case TestStep::kComplete:
      SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kPassed,
                       kBluetoothRoutinePassedMessage);
      break;
  }
}

void BluetoothPowerRoutine::HandleAdapterPoweredChanged(bool is_success) {
  if (!is_success) {
    SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                     kBluetoothRoutineFailedChangePowered);
    return;
  }
}

void BluetoothPowerRoutine::OnAdapterPropertyChanged(
    org::bluez::Adapter1ProxyInterface* adapter,
    const std::string& property_name) {
  if (adapter != GetAdapter() || property_name != adapter->PoweredName() ||
      (step_ != kCheckPoweredStatusOff && step_ != kCheckPoweredStatusOn))
    return;

  // Verify the powered status in HCI level first.
  context_->executor()->GetHciDeviceConfig(
      base::BindOnce(&BluetoothPowerRoutine::HandleHciConfigResponse,
                     weak_ptr_factory_.GetWeakPtr()));
}

void BluetoothPowerRoutine::HandleHciConfigResponse(
    mojom::ExecutedProcessResultPtr result) {
  std::string err = result->err;
  int32_t return_code = result->return_code;

  if (!err.empty() || return_code != EXIT_SUCCESS) {
    SetResultAndStop(
        mojom::DiagnosticRoutineStatusEnum::kError,
        base::StringPrintf(
            "GetHciConfig failed with return code: %d and error: %s",
            return_code, err.c_str()));
    return;
  }

  bool check_powered_off = result->out.find("DOWN") != std::string::npos;
  bool check_powered_on = result->out.find("UP RUNNING") != std::string::npos;
  if (check_powered_off && !check_powered_on) {
    VerifyAdapterPowered(/*hci_powered=*/false);
  } else if (!check_powered_off && check_powered_on) {
    VerifyAdapterPowered(/*hci_powered=*/true);
  } else {
    SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                     "Failed to parse powered status from HCI device config.");
  }
}

void BluetoothPowerRoutine::VerifyAdapterPowered(bool hci_powered) {
  bool is_passed;
  std::string result_key;
  bool dbus_powered = GetAdapter()->powered();

  if (step_ == TestStep::kCheckPoweredStatusOff) {
    // The powered status should be false.
    is_passed = !hci_powered && !dbus_powered;
    result_key = "power_off_result";
  } else if (step_ == TestStep::kCheckPoweredStatusOn) {
    // The powered status should be true.
    is_passed = hci_powered && dbus_powered;
    result_key = "power_on_result";
  } else {
    SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                     kBluetoothRoutineUnexpectedFlow);
    return;
  }

  // Store the result into output dict.
  base::Value::Dict out_result;
  out_result.Set("hci_powered", hci_powered);
  out_result.Set("dbus_powered", dbus_powered);
  output_dict_.Set(result_key, std::move(out_result));

  // Stop routine if validation is failed.
  if (!is_passed) {
    SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kFailed,
                     kBluetoothRoutineFailedVerifyPowered);
    return;
  }
  RunNextStep();
}

void BluetoothPowerRoutine::OnTimeoutOccurred() {
  SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                   "Bluetooth routine failed to complete before timeout.");
}

void BluetoothPowerRoutine::SetResultAndStop(
    mojom::DiagnosticRoutineStatusEnum status,
    const std::string& status_message) {
  // Cancel all pending callbacks.
  weak_ptr_factory_.InvalidateWeakPtrs();
  ResetPoweredState();
  UpdateStatus(status, std::move(status_message));
}

}  // namespace diagnostics
