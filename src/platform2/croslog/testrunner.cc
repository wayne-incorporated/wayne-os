// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task/single_thread_task_executor.h"
#include "common-mk/testrunner.h"

int main(int argc, char** argv) {
  // Declaring SingleThreadTaskExecutor here, since the singleton object
  // FileChangeWatcher depends on the task executor implicitly.
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);

  auto runner = platform2::TestRunner(argc, argv);
  return runner.Run();
}
