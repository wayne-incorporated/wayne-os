// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/syslog_logging.h>
#include <libhwsec-foundation/profiling/profiling.h>

#include "bootlockbox/boot_lockbox_service.h"

int main(int argc, char** argv) {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  // Start profiling.
  hwsec_foundation::SetUpProfiling();

  bootlockbox::BootLockboxService service;
  service.Run();
  return 0;
}
