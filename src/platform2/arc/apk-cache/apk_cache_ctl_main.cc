// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sysexits.h>

#include <iostream>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <brillo/syslog_logging.h>

#include "arc/apk-cache/apk_cache_ctl_commands.h"
#include "arc/apk-cache/apk_cache_utils.h"

namespace {

constexpr char kHelpText[] =
    "APK Cache Utility\n"
    "\n"
    "Usage: apk-cache-ctl COMMAND [OPTIONS]\n"
    "Tool for controlling ARC++ APK Cache.\n"
    "\n"
    "Commands:\n"
    "  ls      List file entries in the database.\n"
    "\n"
    "Options:\n"
    "  --help  Show help for command. Show this help if no command is "
    "specified.";

}  // namespace

int main(int argc, char** argv) {
  // Use "arc-" prefix so that the log is recorded in /var/log/arc.log.
  brillo::OpenLog("arc-apk-cache-ctl", true /* log_pid */);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  std::vector<std::string> args(argv, argv + argc);

  if (args.size() > 0) {
    if (args[1] == "ls") {
      base::FilePath cache_root(apk_cache::kApkCacheDir);
      return static_cast<int>(apk_cache::CommandLs(cache_root, std::cout));
    }
  }

  std::cerr << kHelpText << std::endl;
  return EX_USAGE;
}
