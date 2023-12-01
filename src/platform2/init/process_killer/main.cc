// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <utility>

#include <base/logging.h>

#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <init/process_killer/process_killer.h>

int main(int argc, char* argv[]) {
  DEFINE_bool(log_to_stderr, false, "Logs to stderr.");
  DEFINE_bool(session, false, "Kill session-related processes");
  DEFINE_bool(shutdown, false, "Kill shutdown-related processes");
  DEFINE_bool(file_holders, false, "Kill processes that keep files open");
  DEFINE_bool(
      mount_holders, false,
      "Kill processes that keep mounts open in a non-init mount namespace");
  brillo::FlagHelper::Init(argc, argv, "Chromium OS Process Killer");

  // Add a flag to explicitly log to stderr: this is useful for situations where
  // we want to collect logs in absence of syslog.
  if (FLAGS_log_to_stderr)
    brillo::InitLog(brillo::kLogToStderr);
  else
    brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  if (argc <= 1 || !base::CommandLine::ForCurrentProcess()->GetArgs().empty()) {
    LOG(ERROR) << "process_killer takes no arguments";
    return EXIT_FAILURE;
  }

  std::unique_ptr<init::ProcessKiller> process_killer =
      std::make_unique<init::ProcessKiller>(FLAGS_session, FLAGS_shutdown);

  process_killer->KillProcesses(FLAGS_file_holders, FLAGS_mount_holders);

  return EXIT_SUCCESS;
}
