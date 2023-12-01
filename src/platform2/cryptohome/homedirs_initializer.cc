// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/files/file_path.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>

#include "cryptohome/filesystem_layout.h"
#include "cryptohome/platform.h"

int main(int argc, char** argv) {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  // Read the file before we daemonize so it can be deleted as soon as we exit.
  cryptohome::Platform platform;

  if (!cryptohome::InitializeFilesystemLayout(&platform, nullptr)) {
    return 1;
  }

  return 0;
}
