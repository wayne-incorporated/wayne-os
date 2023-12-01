// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/at_exit.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/message_loops/base_message_loop.h>
#include <brillo/test_helpers.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

int main(int argc, char** argv) {
  SetUpTests(&argc, argv, true);
  base::AtExitManager at_exit;

  (new brillo::BaseMessageLoop())->SetAsCurrent();

  mojo::core::Init();
  mojo::core::ScopedIPCSupport _(
      base::SingleThreadTaskRunner::GetCurrentDefault(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::FAST);

  return RUN_ALL_TESTS();
}
