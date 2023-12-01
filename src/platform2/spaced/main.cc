// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "spaced/daemon.h"

#include <base/logging.h>
#include <brillo/syslog_logging.h>

int main(int argc, char** argv) {
  brillo::InitLog(brillo::kLogToSyslog);
  return spaced::Daemon().Run();
}
