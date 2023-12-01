// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/logging.h>
#include <base/message_loop/message_pump_type.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "vm_tools/notificationd/notification_daemon.h"

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  DEFINE_string(display_name, "", "Wayland display to connect to");
  DEFINE_string(virtwl_device, "", "VirtWL device to use");

  brillo::FlagHelper::Init(argc, argv, "notification daemon");
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  if (cl->GetArgs().size() > 0) {
    LOG(ERROR) << "Unknown extra command line arguments; exiting";
    return EXIT_FAILURE;
  }

  base::RunLoop run_loop;

  auto daemon = vm_tools::notificationd::NotificationDaemon::Create(
      FLAGS_display_name, FLAGS_virtwl_device, run_loop.QuitClosure());

  if (!daemon) {
    LOG(ERROR) << "Failed to initialize notification daemon";
    return EXIT_FAILURE;
  }

  run_loop.Run();

  return EXIT_FAILURE;
}
