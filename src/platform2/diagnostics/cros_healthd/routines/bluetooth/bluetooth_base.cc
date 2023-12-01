// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_base.h"

#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>

#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_constants.h"
#include "diagnostics/cros_healthd/system/bluetooth_info_manager.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

}  // namespace

BluetoothRoutineBase::BluetoothRoutineBase(Context* context)
    : context_(context) {
  DCHECK(context_);
  adapters_ = context->bluetooth_info_manager()->GetAdapters();
}

BluetoothRoutineBase::~BluetoothRoutineBase() = default;

org::bluez::Adapter1ProxyInterface* BluetoothRoutineBase::GetAdapter() const {
  if (adapters_.empty())
    return nullptr;
  return adapters_[0];
}

void BluetoothRoutineBase::EnsureAdapterPoweredState(
    bool powered, base::OnceCallback<void(bool)> on_finish) {
  if (!GetAdapter()) {
    std::move(on_finish).Run(false);
    return;
  }
  // Already on or off.
  if (powered == GetAdapter()->powered()) {
    std::move(on_finish).Run(true);
    return;
  }
  GetAdapter()->set_powered(powered, std::move(on_finish));
}

void BluetoothRoutineBase::RunPreCheck(
    base::OnceClosure on_passed,
    base::OnceCallback<void(mojom::DiagnosticRoutineStatusEnum status,
                            const std::string& error_message)> on_failed) {
  if (!GetAdapter()) {
    std::move(on_failed).Run(mojom::DiagnosticRoutineStatusEnum::kError,
                             kBluetoothRoutineFailedGetAdapter);
    return;
  }

  // Ensure the adapter is not in discovery mode. We should avoid running
  // Bluetooth routines when the adapter is actively scaninng or pairing.
  initial_powered_state_ = GetAdapter()->powered();
  if (initial_powered_state_.value() && GetAdapter()->discovering()) {
    std::move(on_failed).Run(mojom::DiagnosticRoutineStatusEnum::kFailed,
                             kBluetoothRoutineFailedDiscoveryMode);
    return;
  }

  std::move(on_passed).Run();
}

void BluetoothRoutineBase::ResetPoweredState() {
  if (!initial_powered_state_.has_value()) {
    return;
  }
  EnsureAdapterPoweredState(initial_powered_state_.value(), base::DoNothing());
}

}  // namespace diagnostics
