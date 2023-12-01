// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_MOCK_FRONTEND_H_
#define LIBHWSEC_FRONTEND_MOCK_FRONTEND_H_

#include <memory>
#include <utility>

#include <base/task/single_thread_task_runner.h>
#include <base/task/task_runner.h>
#include <base/threading/thread.h>

#include "libhwsec/middleware/middleware_derivative.h"

namespace hwsec {

class MockFrontend {
 public:
  MockFrontend() {}
  virtual ~MockFrontend() = default;

  MiddlewareDerivative GetFakeMiddlewareDerivative() {
    return MiddlewareDerivative{
        .task_runner = base::SequencedTaskRunner::HasCurrentDefault()
                           ? base::SequencedTaskRunner::GetCurrentDefault()
                           : nullptr,
        .thread_id = base::PlatformThread::CurrentId(),
        .middleware = nullptr,
    };
  }
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_MOCK_FRONTEND_H_
