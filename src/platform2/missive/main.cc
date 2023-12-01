// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <base/task/thread_pool/thread_pool_instance.h>

#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "missive/daemon/missive_daemon.h"

namespace {

void SetLogItems() {
  const bool kOptionPID = true;
  const bool kOptionTID = true;
  const bool kOptionTimestamp = true;
  const bool kOptionTickcount = true;
  logging::SetLogItems(kOptionPID, kOptionTID, kOptionTimestamp,
                       kOptionTickcount);
}

}  // namespace

int main(int argc, char* argv[]) {
  brillo::FlagHelper::Init(argc, argv,
                           "missive_daemon - Administrative device "
                           "event logging daemon.");

  // Always log to syslog and log to stderr if we are connected to a tty.
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  // Override the log items set by brillo::InitLog.
  SetLogItems();

  base::ThreadPoolInstance::CreateAndStartWithDefaultParams(
      "missive_daemon_thread_pool");

  LOG(INFO) << "Starting Missive Service.";
  const int exit_code = ::reporting::MissiveDaemon().Run();
  LOG(INFO) << "Missive Service ended with exit_code=" << exit_code;

  return exit_code;
}
