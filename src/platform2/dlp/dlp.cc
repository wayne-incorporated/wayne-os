// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/syslog_logging.h>

#include "dlp/dlp_daemon.h"

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();

  brillo::OpenLog("dlp", true /* log_pid */);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  // Check 4 parameters in format <fanotify_perm_fd, fanotify_notif_fd,
  // home_dir, database_dir>.
  if (cl->GetArgs().size() < 4) {
    LOG(ERROR) << "Not enough parameters to start DLP daemon";
    return 1;
  }
  int fanotify_perm_fd;
  CHECK(base::StringToInt(cl->GetArgs()[0], &fanotify_perm_fd))
      << "first parameter should be a fanotify fd";
  int fanotify_notif_fd;
  CHECK(base::StringToInt(cl->GetArgs()[1], &fanotify_notif_fd))
      << "second parameter should be a fanotify fd";
  base::FilePath home_dir = base::FilePath(cl->GetArgs()[2]);
  if (!base::DirectoryExists(home_dir)) {
    LOG(ERROR) << "home path " << home_dir << " does not exist.";
    return 1;
  }
  base::FilePath database_dir = base::FilePath(cl->GetArgs()[3]);
  if (!base::DirectoryExists(database_dir)) {
    LOG(ERROR) << "database-dir " << database_dir << " does not exist.";
    return 1;
  }

  // Run daemon.
  LOG(INFO) << "DLP daemon starting";
  dlp::DlpDaemon daemon(fanotify_perm_fd, fanotify_notif_fd, home_dir,
                        database_dir);
  int result = daemon.Run();
  LOG(INFO) << "DLP daemon stopping with exit code " << result;

  return 0;
}
