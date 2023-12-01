// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include <base/functional/callback_helpers.h>

#include "diagnostics/cros_healthd/executor/utils/scoped_process_control.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

}  // namespace

struct ScopedProcessControl::ProcessControlState {
  // A boolean to indicate whether the process wrapped by Process Control has
  // already terminated.
  bool has_terminated;
  // A boolean to indicate whether the state should be deleted.
  bool should_be_deleted;
  // Callbacks that will be run once the process terminates.
  // ScopedClosureRunner will automatically run when the callbacks are
  // destructed.
  std::vector<base::ScopedClosureRunner> on_terminate_callbacks;

  // The remote that will control the lifecycle of ProcessControlState.
  // Must be the last member of the struct.
  mojo::Remote<mojom::ProcessControl> process_control_remote;
};

namespace {

void OnProcessTermination(ScopedProcessControl::ProcessControlState* state) {
  state->on_terminate_callbacks.clear();
  state->has_terminated = true;
  if (state->should_be_deleted) {
    state->process_control_remote.reset();
    delete state;
  }
}

}  // namespace

ScopedProcessControl::ScopedProcessControl() {
  // The State is created using new to outlive the lifetime of
  // ScopedProcessControl. It will be deleted when the process has been properly
  // killed.
  state_ = new ProcessControlState();
}

ScopedProcessControl::~ScopedProcessControl() {
  if (state_ != nullptr) {
    Reset();
  }
}

void ScopedProcessControl::Reset() {
  CHECK(state_) << "state pointer is invalid";
  // Don't attempt to call ProcessControl method if the remote is not bound, and
  // no need to kill and wait again if the process has already terminated.
  if (!state_->process_control_remote.is_bound() || state_->has_terminated) {
    delete state_;
    state_ = nullptr;
    return;
  }
  // Kill the running process.
  state_->process_control_remote->Kill();
  // Set flag such that state_ will be deleted once the process is terminated.
  state_->should_be_deleted = true;
  state_ = nullptr;
}

mojo::PendingReceiver<mojom::ProcessControl>
ScopedProcessControl::BindNewPipeAndPassReceiver() {
  CHECK(state_) << "state pointer is invalid";
  auto pending_receiver =
      state_->process_control_remote.BindNewPipeAndPassReceiver();
  // If the process terminates, run all the on terminate callbacks.
  state_->process_control_remote->GetReturnCode(
      base::IgnoreArgs<int32_t>(base::BindOnce(&OnProcessTermination, state_)));
  // If the remote disconnects, run all the on terminate callbacks.
  state_->process_control_remote.set_disconnect_handler(
      base::IgnoreArgs<>(base::BindOnce(&OnProcessTermination, state_)));
  return pending_receiver;
}

void ScopedProcessControl::AddOnTerminateCallback(
    base::ScopedClosureRunner callback) {
  CHECK(state_) << "state pointer is invalid";
  if (state_->has_terminated) {
    std::move(callback).RunAndReset();
    return;
  }
  state_->on_terminate_callbacks.push_back(std::move(callback));
}

mojom::ProcessControl* ScopedProcessControl::operator->() {
  CHECK(state_) << "state pointer is invalid";
  return state_->process_control_remote.get();
}

}  // namespace diagnostics
