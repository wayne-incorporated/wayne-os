// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/syslog_logging.h>

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_executor.h>
#include <base/threading/thread.h>

#include "arc/vm/mojo_proxy/server_proxy.h"

int main(int argc, char** argv) {
  // Initialize CommandLine for VLOG before InitLog.
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader |
                  brillo::kLogToStderrIfTty);

  if (argc < 2) {
    LOG(ERROR) << "Mount path is not specified.";
    return 1;
  }
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher_{task_executor.task_runner()};

  base::Thread proxy_file_system_thread{"ProxyFileSystem"};
  if (!proxy_file_system_thread.StartWithOptions(
          base::Thread::Options(base::MessagePumpType::IO, 0))) {
    LOG(ERROR) << "Failed to start ProxyFileSystem thread.";
    return 1;
  }

  base::RunLoop run_loop;
  arc::ServerProxy server_proxy(proxy_file_system_thread.task_runner(),
                                base::FilePath(argv[1]),
                                run_loop.QuitClosure());
  if (!server_proxy.Initialize()) {
    LOG(ERROR) << "Failed to initialize ServerProxy.";
    return 1;
  }
  run_loop.Run();
  return 0;
}
