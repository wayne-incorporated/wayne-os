// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MOJO_SERVICE_MANAGER_TESTING_MOJO_TEST_ENVIRONMENT_H_
#define MOJO_SERVICE_MANAGER_TESTING_MOJO_TEST_ENVIRONMENT_H_

#include <base/task/single_thread_task_runner.h>
#include <base/test/task_environment.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

namespace chromeos {
namespace mojo_service_manager {

// Sets up test environment for mojo.
class MojoTaskEnvironment : public base::test::SingleThreadTaskEnvironment {
 public:
  template <class... ArgTypes>
  explicit MojoTaskEnvironment(ArgTypes... args)
      : base::test::SingleThreadTaskEnvironment(MainThreadType::IO, args...),
        ipc_support_(base::SingleThreadTaskRunner::GetCurrentDefault(),
                     mojo::core::ScopedIPCSupport::ShutdownPolicy::
                         CLEAN /* blocking shutdown */) {}

 private:
  mojo::core::ScopedIPCSupport ipc_support_;
};

}  // namespace mojo_service_manager
}  // namespace chromeos

#endif  // MOJO_SERVICE_MANAGER_TESTING_MOJO_TEST_ENVIRONMENT_H_
