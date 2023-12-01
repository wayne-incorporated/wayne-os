// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VIRTUAL_FILE_PROVIDER_OPERATION_THROTTLE_H_
#define VIRTUAL_FILE_PROVIDER_OPERATION_THROTTLE_H_

#include <memory>

#include <base/functional/callback_helpers.h>
#include <base/synchronization/condition_variable.h>
#include <base/synchronization/lock.h>

namespace virtual_file_provider {

// OperationThrottle limits the number of operations running at the same time,
// by blocking new operations until existing one finishes.
class OperationThrottle {
 public:
  explicit OperationThrottle(int max_operation_count);
  OperationThrottle(const OperationThrottle&) = delete;
  OperationThrottle& operator=(const OperationThrottle&) = delete;

  ~OperationThrottle();

  // Increments the operation counter, possibly after blocking the caller until
  // other operations finish.
  // The caller should keep the returned object alive until the operation
  // finishes.
  std::unique_ptr<base::ScopedClosureRunner> StartOperation();

 private:
  void FinishOperation();

  const int max_operation_count_;
  int operation_count_ = 0;
  base::Lock lock_;
  base::ConditionVariable operation_count_changed_condition_;
};

}  // namespace virtual_file_provider

#endif  // VIRTUAL_FILE_PROVIDER_OPERATION_THROTTLE_H_
