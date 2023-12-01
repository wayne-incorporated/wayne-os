// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>

#include "cryptohome/lockbox-cache.h"
#include "cryptohome/platform.h"

namespace switches {
static const char* kNvramPath = "nvram";
static const char* kUnlinkNvram = "unlink-nvram";
static const char* kLockboxPath = "lockbox";
static const char* kCachePath = "cache";
}  // namespace switches

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  // Allow the commands to be configurable.
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  base::FilePath nvram_path(cl->GetSwitchValueASCII(switches::kNvramPath));
  base::FilePath lockbox_path(cl->GetSwitchValueASCII(switches::kLockboxPath));
  base::FilePath cache_path(cl->GetSwitchValueASCII(switches::kCachePath));
  if (nvram_path.empty() || lockbox_path.empty() || cache_path.empty()) {
    LOG(ERROR) << "Paths for --cache, --lockbox, and --nvram must be supplied.";
    return 1;
  }

  cryptohome::Platform platform;
  bool ok = CacheLockbox(&platform, nvram_path, lockbox_path, cache_path);
  if (cl->HasSwitch(switches::kUnlinkNvram))
    platform.DeleteFile(nvram_path);
  if (!ok)
    platform.DeleteFile(cache_path);
  return !ok;
}
