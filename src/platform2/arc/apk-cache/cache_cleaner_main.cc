// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "arc/apk-cache/apk_cache_utils.h"
#include "arc/apk-cache/cache_cleaner.h"
#include "arc/apk-cache/cache_cleaner_db.h"

namespace {

constexpr char kHelpText[] =
    "Performs cleaning of the APK cache directory: "
    "/mnt/stateful_partition/unencrypted/apkcache/\n"
    "It removes:\n"
    " - all the files in the cache root;\n"
    " - all the package directories that:\n"
    "   1. have not been used within last 30 days;\n"
    "   2. contain unexpected files. Any file except APK, main and patch OBB\n"
    "      and JSON with package attributes is considered unexpected;\n"
    "   3. contain directories;\n"
    "   4. contain no or more than one APK file, no attributes JSON file,\n"
    "      more then one main OBB file, more then one patch OBB file.\n"
    "Returns 0 all the intended files and directories were successfully\n"
    "deleted.";

}  // namespace

int main(int argc, char** argv) {
  // Use "arc-" prefix so that the log is recorded in /var/log/arc.log.
  brillo::OpenLog("arc-apk-cache-cleaner", true /* log_pid */);
  brillo::FlagHelper::Init(argc, argv, kHelpText);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  base::FilePath cache_root(apk_cache::kApkCacheDir);
  if (!apk_cache::Clean(cache_root)) {
    LOG(ERROR) << "APK Cache cleaner experienced problem while cleaning.";
    return 1;
  }
  apk_cache::OpaqueFilesCleaner cleaner(cache_root);
  if (!cleaner.Clean()) {
    LOG(ERROR) << "APK Cache cleaner experienced problem while cleaning.";
    return 1;
  }

  LOG(INFO) << "APK Cache cleaner succeeded.";
  return 0;
}
