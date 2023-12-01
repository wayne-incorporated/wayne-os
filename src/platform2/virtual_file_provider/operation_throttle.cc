// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "virtual_file_provider/operation_throttle.h"

#include <base/check_op.h>
#include <base/functional/bind.h>

namespace virtual_file_provider {

OperationThrottle::OperationThrottle(int max_operation_count)
    : max_operation_count_(max_operation_count),
      operation_count_changed_condition_(&lock_) {}

OperationThrottle::~OperationThrottle() {
  DCHECK_EQ(0, operation_count_);
}

std::unique_ptr<base::ScopedClosureRunner> OperationThrottle::StartOperation() {
  base::AutoLock lock(lock_);
  while (operation_count_ >= max_operation_count_) {
    operation_count_changed_condition_.Wait();
  }
  ++operation_count_;
  return std::make_unique<base::ScopedClosureRunner>(base::BindOnce(
      &OperationThrottle::FinishOperation, base::Unretained(this)));
}

void OperationThrottle::FinishOperation() {
  base::AutoLock lock(lock_);
  --operation_count_;
  operation_count_changed_condition_.Signal();
}

}  // namespace virtual_file_provider
