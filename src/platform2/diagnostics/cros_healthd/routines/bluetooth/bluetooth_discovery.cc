// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_discovery.h"

#include <algorithm>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <re2/re2.h>

#include "diagnostics/base/mojo_utils.h"
#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_constants.h"
#include "diagnostics/cros_healthd/system/bluetooth_event_hub.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

}  // namespace

BluetoothDiscoveryRoutine::BluetoothDiscoveryRoutine(Context* context)
    : BluetoothRoutineBase(context) {}

BluetoothDiscoveryRoutine::~BluetoothDiscoveryRoutine() = default;

void BluetoothDiscoveryRoutine::Start() {
  DCHECK_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);

  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning,
               kBluetoothRoutineRunningMessage);
  start_ticks_ = base::TimeTicks::Now();

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&BluetoothDiscoveryRoutine::OnTimeoutOccurred,
                     weak_ptr_factory_.GetWeakPtr()),
      kRoutineDiscoveryTimeout);

  event_subscriptions_.push_back(
      context_->bluetooth_event_hub()->SubscribeAdapterPropertyChanged(
          base::BindRepeating(
              &BluetoothDiscoveryRoutine::OnAdapterPropertyChanged,
              weak_ptr_factory_.GetWeakPtr())));

  RunPreCheck(
      /*on_passed=*/base::BindOnce(&BluetoothDiscoveryRoutine::RunNextStep,
                                   weak_ptr_factory_.GetWeakPtr()),
      /*on_failed=*/base::BindOnce(&BluetoothDiscoveryRoutine::SetResultAndStop,
                                   weak_ptr_factory_.GetWeakPtr()));
}

void BluetoothDiscoveryRoutine::Resume() {
  LOG(ERROR) << "Bluetooth discovery routine cannot be resumed";
}

void BluetoothDiscoveryRoutine::Cancel() {
  LOG(ERROR) << "Bluetooth discovery routine cannot be cancelled";
}

void BluetoothDiscoveryRoutine::PopulateStatusUpdate(
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
      (base::TimeTicks::Now() - start_ticks_) / kRoutineDiscoveryTimeout;
  response->progress_percent =
      step_percent + (100 - step_percent) * std::min(1.0, running_time_ratio);
}

void BluetoothDiscoveryRoutine::RunNextStep() {
  step_ = static_cast<TestStep>(static_cast<int>(step_) + 1);

  switch (step_) {
    case TestStep::kInitialize:
      SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                       kBluetoothRoutineUnexpectedFlow);
      break;
    case TestStep::kEnsurePoweredOn:
      EnsureAdapterPoweredState(
          /*powered=*/true,
          base::BindOnce(&BluetoothDiscoveryRoutine::HandleAdapterPoweredOn,
                         weak_ptr_factory_.GetWeakPtr()));
      break;
    case TestStep::kCheckDiscoveringStatusOn:
      // Wait for the property changed event in |OnAdapterPropertyChanged|.
      GetAdapter()->StartDiscoveryAsync(
          base::DoNothing(),
          base::BindOnce(
              &BluetoothDiscoveryRoutine::HandleAdapterDiscoveryError,
              weak_ptr_factory_.GetWeakPtr()));
      break;
    case TestStep::kCheckDiscoveringStatusOff:
      // Wait for the property changed event in |OnAdapterPropertyChanged|.
      GetAdapter()->StopDiscoveryAsync(
          base::DoNothing(),
          base::BindOnce(
              &BluetoothDiscoveryRoutine::HandleAdapterDiscoveryError,
              weak_ptr_factory_.GetWeakPtr()));
      break;
    case TestStep::kComplete:
      SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kPassed,
                       kBluetoothRoutinePassedMessage);
      break;
  }
}

void BluetoothDiscoveryRoutine::HandleAdapterPoweredOn(bool is_success) {
  if (!is_success) {
    SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                     kBluetoothRoutineFailedChangePowered);
    return;
  }
  RunNextStep();
}

void BluetoothDiscoveryRoutine::HandleAdapterDiscoveryError(
    brillo::Error* error) {
  if (error) {
    LOG(ERROR) << "Failed to change discovering status, error message: "
               << error->GetMessage();
  }
  SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                   kBluetoothRoutineFailedSwitchDiscovery);
}

void BluetoothDiscoveryRoutine::OnAdapterPropertyChanged(
    org::bluez::Adapter1ProxyInterface* adapter,
    const std::string& property_name) {
  if (adapter != GetAdapter() || property_name != adapter->DiscoveringName() ||
      (step_ != kCheckDiscoveringStatusOn &&
       step_ != kCheckDiscoveringStatusOff))
    return;

  // Check the discovering status in HCI level.
  context_->executor()->GetHciDeviceConfig(
      base::BindOnce(&BluetoothDiscoveryRoutine::HandleHciConfigResponse,
                     weak_ptr_factory_.GetWeakPtr(),
                     /*dbus_discovering=*/adapter->discovering()));
}

void BluetoothDiscoveryRoutine::HandleHciConfigResponse(
    bool dbus_discovering, mojom::ExecutedProcessResultPtr result) {
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

  // Assert the adapter powered status in HCI level is not off.
  if (result->out.find("UP RUNNING") == std::string::npos) {
    SetResultAndStop(
        mojom::DiagnosticRoutineStatusEnum::kError,
        "Failed to ensure powered status is on from HCI device config.");
    return;
  }

  // Example of HCI config output:
  // hci0:   <some texts>
  //         <texts>
  //         UP RUNNING PSCAN INQUIRY
  //         <texts>
  const char inquiry_regex[] = R"(UP RUNNING.*INQUIRY)";
  bool hci_discovering = RE2::PartialMatch(result->out, inquiry_regex);
  VerifyAdapterDiscovering(dbus_discovering, hci_discovering);
}

void BluetoothDiscoveryRoutine::VerifyAdapterDiscovering(bool dbus_discovering,
                                                         bool hci_discovering) {
  bool is_passed;
  std::string result_key;
  if (step_ == TestStep::kCheckDiscoveringStatusOn) {
    // The discovering status should be true.
    is_passed = hci_discovering && dbus_discovering;
    result_key = "start_discovery_result";
  } else if (step_ == TestStep::kCheckDiscoveringStatusOff) {
    // The discovering status should be false.
    is_passed = !hci_discovering && !dbus_discovering;
    result_key = "stop_discovery_result";
  } else {
    SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                     kBluetoothRoutineUnexpectedFlow);
    return;
  }

  // Store the result into output dict.
  base::Value::Dict out_result;
  out_result.Set("hci_discovering", hci_discovering);
  out_result.Set("dbus_discovering", dbus_discovering);
  output_dict_.Set(result_key, std::move(out_result));

  // Stop routine if validation is failed.
  if (!is_passed) {
    SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kFailed,
                     kBluetoothRoutineFailedVerifyDiscovering);
    return;
  }
  RunNextStep();
}

void BluetoothDiscoveryRoutine::OnTimeoutOccurred() {
  SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                   "Bluetooth routine failed to complete before timeout.");
}

void BluetoothDiscoveryRoutine::SetResultAndStop(
    mojom::DiagnosticRoutineStatusEnum status,
    const std::string& status_message) {
  // Make the adapter stop discovery when routine is stopped.
  if (step_ == TestStep::kCheckDiscoveringStatusOn) {
    GetAdapter()->StopDiscoveryAsync(base::DoNothing(), base::DoNothing());
  }
  // Cancel all pending callbacks.
  weak_ptr_factory_.InvalidateWeakPtrs();
  UpdateStatus(status, std::move(status_message));
}

}  // namespace diagnostics
