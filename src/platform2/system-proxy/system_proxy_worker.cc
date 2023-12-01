// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <string>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/task/single_thread_task_executor.h>
#include <base/run_loop.h>

#include "system-proxy/server_proxy.h"

int main(int argc, char* argv[]) {
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());
  base::RunLoop run_loop;

  system_proxy::ServerProxy server(run_loop.QuitClosure());
  server.Init();
  run_loop.Run();
  return 0;
}
