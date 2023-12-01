// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_executor.h>
#include <base/time/time.h>
#include <brillo/daemons/daemon.h>
#include <brillo/flag_helper.h>

#include "biod/biod_version.h"
#include "biod/biometrics_daemon.h"

int main(int argc, char* argv[]) {
  base::AtExitManager at_exit_manager;

  DEFINE_string(log_dir, "/var/log/biod", "Directory where logs are written.");

  brillo::FlagHelper::Init(argc, argv,
                           "biod, the Chromium OS biometrics daemon.");

  const base::FilePath log_file =
      base::FilePath(FLAGS_log_dir)
          .Append(base::StringPrintf(
              "biod.%s",
              brillo::GetTimeAsLogString(base::Time::Now()).c_str()));
  brillo::UpdateLogSymlinks(
      base::FilePath(FLAGS_log_dir).Append("biod.LATEST"),
      base::FilePath(FLAGS_log_dir).Append("biod.PREVIOUS"), log_file);

  logging::LoggingSettings logging_settings;
  logging_settings.logging_dest = logging::LOG_TO_FILE;
  logging_settings.log_file_path = log_file.value().c_str();
  logging_settings.lock_log = logging::DONT_LOCK_LOG_FILE;
  logging::InitLogging(logging_settings);
  logging::SetLogItems(true,    // process ID
                       true,    // thread ID
                       true,    // timestamp
                       false);  // tickcount

  biod::LogVersion();

  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());
  biod::BiometricsDaemon bio_daemon;
  base::RunLoop().Run();
  return 0;
}
