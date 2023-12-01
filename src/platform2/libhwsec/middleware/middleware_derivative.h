// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_MIDDLEWARE_MIDDLEWARE_DERIVATIVE_H_
#define LIBHWSEC_MIDDLEWARE_MIDDLEWARE_DERIVATIVE_H_

#include <base/memory/weak_ptr.h>
#include <base/task/task_runner.h>
#include <base/threading/thread.h>

namespace hwsec {

class MiddlewareOwner;

// This structure contains the required information to running task on the
// middleware. It can be derived from the MiddleOwner.
struct MiddlewareDerivative {
  scoped_refptr<base::TaskRunner> task_runner;
  base::PlatformThreadId thread_id;
  base::WeakPtr<MiddlewareOwner> middleware;
};

}  // namespace hwsec

#endif  // LIBHWSEC_MIDDLEWARE_MIDDLEWARE_DERIVATIVE_H_
