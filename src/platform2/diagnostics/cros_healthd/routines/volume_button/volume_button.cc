// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/volume_button/volume_button.h"

#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>

#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

// Define the max timeout in the unit of seconds to align with documents easily.
constexpr int kMaxTimeoutSeconds = 600;
constexpr base::TimeDelta kMaxTimeout = base::Seconds(kMaxTimeoutSeconds);

bool IsButtonTypeMatched(
    mojom::VolumeButtonObserver::Button got_button,
    mojom::VolumeButtonRoutineArgument::ButtonType expect_button) {
  switch (got_button) {
    case mojom::VolumeButtonObserver::Button::kVolumeUp:
      return expect_button ==
             mojom::VolumeButtonRoutineArgument::ButtonType::kVolumeUp;
    case mojom::VolumeButtonObserver::Button::kVolumeDown:
      return expect_button ==
             mojom::VolumeButtonRoutineArgument::ButtonType::kVolumeDown;
  }
}

}  // namespace

VolumeButtonRoutine::VolumeButtonRoutine(
    Context* context, const mojom::VolumeButtonRoutineArgumentPtr& arg)
    : target_button_type_(arg->type),
      timeout_(arg->timeout),
      context_(context) {
  CHECK(context_);
}

VolumeButtonRoutine::~VolumeButtonRoutine() = default;

void VolumeButtonRoutine::OnStart() {
  if (target_button_type_ ==
      mojom::VolumeButtonRoutineArgument::ButtonType::kUnmappedEnumField) {
    RaiseException("Unknown volume button type.");
    return;
  }
  if (!timeout_.is_positive()) {
    LOG(ERROR) << "Timeout for volume button routine is not positive: "
               << timeout_;
    RaiseException("Timeout must be positive.");
    return;
  }
  if (timeout_ > kMaxTimeout) {
    LOG(ERROR) << "Timeout for volume button is invalid: " << timeout_;
    RaiseException(base::StringPrintf(
        "Timeout cannot be longer than %d seconds.", kMaxTimeoutSeconds));
    return;
  }

  SetRunningState();

  context_->executor()->MonitorVolumeButton(
      receiver_.BindNewPipeAndPassRemote(),
      process_control_.BindNewPipeAndPassReceiver());
  receiver_.set_disconnect_with_reason_handler(
      base::BindOnce(&VolumeButtonRoutine::OnEventObserverDisconnect,
                     weak_ptr_factory_.GetWeakPtr()));

  timeout_callback_.Reset(base::BindOnce(&VolumeButtonRoutine::OnTimeout,
                                         weak_ptr_factory_.GetWeakPtr()));
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, timeout_callback_.callback(), timeout_);
}

void VolumeButtonRoutine::OnEvent(
    mojom::VolumeButtonObserver::Button button,
    mojom::VolumeButtonObserver::ButtonState button_state) {
  if (IsButtonTypeMatched(button, target_button_type_)) {
    CleanUp();
    SetFinishedState(/*has_passed*/ true,
                     mojom::RoutineDetail::NewVolumeButton(
                         mojom::VolumeButtonRoutineDetail::New()));
  }
}

void VolumeButtonRoutine::OnTimeout() {
  CleanUp();
  SetFinishedState(/*has_passed*/ false,
                   mojom::RoutineDetail::NewVolumeButton(
                       mojom::VolumeButtonRoutineDetail::New()));
}

void VolumeButtonRoutine::OnEventObserverDisconnect(
    uint32_t custom_reason, const std::string& description) {
  LOG(ERROR) << "Volume button monitor disconnect: " << description;
  CleanUp();
  RaiseException("Unable to listen for volume button events.");
}

void VolumeButtonRoutine::CleanUp() {
  receiver_.reset();
  process_control_.reset();
  timeout_callback_.Cancel();
}

}  // namespace diagnostics
