// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/at_exit.h>
#include <base/check.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/logging.h>
#include <base/message_loop/message_pump_type.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "vm_tools/concierge/service.h"

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  brillo::FlagHelper::Init(argc, argv, "vm_concierge service");

  if (argc != 1) {
    LOG(ERROR) << "Unexpected command line arguments";
    return EXIT_FAILURE;
  }

  base::RunLoop run_loop;

  auto service = vm_tools::concierge::Service::Create(run_loop.QuitClosure());
  CHECK(service);

  run_loop.Run();

  return 0;
}
