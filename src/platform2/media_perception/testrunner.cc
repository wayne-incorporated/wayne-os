// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/flag_helper.h>
#include <brillo/message_loops/base_message_loop.h>
#include <brillo/test_helpers.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

int main(int argc, char** argv) {
  SetUpTests(&argc, argv, true);
  base::AtExitManager exit_manager;

  (new brillo::BaseMessageLoop())->SetAsCurrent();

  mojo::core::Init();
  std::unique_ptr<mojo::core ::ScopedIPCSupport> ipc_support_ =
      std::make_unique<mojo::core::ScopedIPCSupport>(
          base::SingleThreadTaskRunner::GetCurrentDefault(),
          mojo::core::ScopedIPCSupport::ShutdownPolicy::FAST);

  return RUN_ALL_TESTS();
}
