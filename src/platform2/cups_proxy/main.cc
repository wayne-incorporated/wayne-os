// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <base/logging.h>
#include <base/task/thread_pool/thread_pool_instance.h>
#include <brillo/syslog_logging.h>

#include "cups_proxy/daemon.h"

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);
  base::ThreadPoolInstance::CreateAndStartWithDefaultParams("cups_proxy");

  return cups_proxy::Daemon().Run();
}
