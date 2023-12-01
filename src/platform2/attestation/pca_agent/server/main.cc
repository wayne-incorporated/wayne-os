// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <brillo/syslog_logging.h>
#include <libhwsec-foundation/profiling/profiling.h>

#include "attestation/pca_agent/server/pca_agent_daemon.h"

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();

  // Start profiling.
  hwsec_foundation::SetUpProfiling();

  int flags = brillo::kLogToSyslog;
  if (cl->HasSwitch("log_to_stderr")) {
    flags |= brillo::kLogToStderr;
  }
  brillo::InitLog(flags);

  return attestation::pca_agent::PcaAgentDaemon().Run();
}
