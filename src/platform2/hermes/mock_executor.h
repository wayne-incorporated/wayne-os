// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_MOCK_EXECUTOR_H_
#define HERMES_MOCK_EXECUTOR_H_

#include <base/test/test_mock_time_task_runner.h>

#include "hermes/executor.h"

namespace hermes {

class MockExecutor : public Executor {
 public:
  MockExecutor() : Executor(new base::TestMockTimeTaskRunner()) {}
  void FastForwardBy(base::TimeDelta duration) {
    scoped_refptr<base::TestMockTimeTaskRunner> mock_task_runner_(
        dynamic_cast<base::TestMockTimeTaskRunner*>(task_runner().get()));
    mock_task_runner_->FastForwardBy(duration);
  }
};

}  // namespace hermes

#endif  // HERMES_MOCK_EXECUTOR_H_
