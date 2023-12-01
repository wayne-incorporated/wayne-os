// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>
#include <sys/mount.h>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/logging.h>
#include <base/message_loop/message_pump_type.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/syslog_logging.h>

#include "vm_tools/seneschal/service.h"

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  if (argc != 1) {
    LOG(ERROR) << "Unexpected command line arguments";
    return EXIT_FAILURE;
  }

  // Make /run/seneschal a shared mount point in our namespace.
  if (mount("/run/seneschal", "/run/seneschal", "none", MS_BIND | MS_REC,
            nullptr) != 0) {
    PLOG(ERROR) << "Failed to bind mount /run/seneschal";
    return EXIT_FAILURE;
  }
  if (mount("none", "/run/seneschal", nullptr, MS_SHARED, nullptr) != 0) {
    PLOG(ERROR) << "Failed to make /run/seneschal a shared mountpoint";
    return EXIT_FAILURE;
  }

  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());
  base::RunLoop run_loop;

  auto service = vm_tools::seneschal::Service::Create(run_loop.QuitClosure());

  CHECK(service);

  run_loop.Run();

  return EXIT_SUCCESS;
}
