// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/utils/resource_queue.h"

#include <ostream>
#include <utility>

#include <base/check_op.h>

namespace diagnostics {

ResourceQueue::ResourceQueue() {
  is_locked_ = false;
}

ResourceQueue::~ResourceQueue() = default;

void ResourceQueue::Enqueue(OnResourceReadyCallback cb) {
  resource_queue_.push(std::move(cb));
  TryToRunNextTask();
}

void ResourceQueue::TryToRunNextTask() {
  if (!is_locked_ && !resource_queue_.empty()) {
    is_locked_ = true;
    OnResourceReadyCallback job = std::move(resource_queue_.front());
    resource_queue_.pop();
    std::move(job).Run(base::ScopedClosureRunner(base::BindOnce(
        &ResourceQueue::ReleaseLock, weak_ptr_factory_.GetWeakPtr())));
  }
}

void ResourceQueue::ReleaseLock() {
  is_locked_ = false;
  TryToRunNextTask();
}

}  // namespace diagnostics
