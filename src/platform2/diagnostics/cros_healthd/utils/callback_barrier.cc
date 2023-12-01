// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/utils/callback_barrier.h"

#include <ostream>
#include <utility>

#include <base/check_op.h>

namespace diagnostics {
namespace {

void OnFinish(base::OnceClosure on_success,
              base::OnceClosure on_error,
              bool success) {
  if (success) {
    std::move(on_success).Run();
  } else {
    std::move(on_error).Run();
  }
}

}  // namespace

CallbackBarrier::CallbackBarrier(base::OnceCallback<void(bool)> on_finish)
    : tracker_(base::MakeRefCounted<CallbackBarrier::Tracker>(
          std::move(on_finish))) {}

CallbackBarrier::CallbackBarrier(base::OnceClosure on_success,
                                 base::OnceClosure on_error)
    : CallbackBarrier(base::BindOnce(
          &OnFinish, std::move(on_success), std::move(on_error))) {}

CallbackBarrier::~CallbackBarrier() = default;

CallbackBarrier::Tracker::Tracker(base::OnceCallback<void(bool)> on_finish)
    : on_finish_(std::move(on_finish)) {}

CallbackBarrier::Tracker::~Tracker() {
  std::move(on_finish_).Run(num_uncalled_callback_ == 0);
}

base::OnceClosure CallbackBarrier::CreateDependencyClosure() {
  // If this closure is dropped, |DecreaseUncalledCallbackNum| won't be called
  // so we know that there is an uncalled dependency.
  tracker_->IncreaseUncalledCallbackNum();
  return base::BindOnce(&Tracker::DecreaseUncalledCallbackNum, tracker_);
}

void CallbackBarrier::Tracker::IncreaseUncalledCallbackNum() {
  ++num_uncalled_callback_;
}

void CallbackBarrier::Tracker::DecreaseUncalledCallbackNum() {
  CHECK_GE(num_uncalled_callback_, 1)
      << "This should never be called when the counter is 0";
  --num_uncalled_callback_;
}

}  // namespace diagnostics
