// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <signal.h>
#include <sysexits.h>

#include <base/command_line.h>
#include <brillo/syslog_logging.h>
#include <libhwsec-foundation/profiling/profiling.h>
#include <libhwsec-foundation/tpm_error/tpm_error_uma_reporter.h>

#include "vtpm/commands/null_command.h"
#include "vtpm/commands/virtualizer.h"
#include "vtpm/vtpm_daemon.h"

void MaskSignals() {
  sigset_t signal_mask;
  CHECK_EQ(0, sigemptyset(&signal_mask));
  for (int signal : {SIGTERM, SIGINT}) {
    CHECK_EQ(0, sigaddset(&signal_mask, signal));
  }
  CHECK_EQ(0, sigprocmask(SIG_BLOCK, &signal_mask, nullptr));
}

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  int flags = brillo::kLogToSyslog;
  if (cl->HasSwitch("log_to_stderr")) {
    flags |= brillo::kLogToStderr;
  }
  brillo::InitLog(flags);

  // Mask signals handled by the daemon thread. This makes sure we
  // won't handle shutdown signals on one of the other threads spawned
  // below.
  MaskSignals();

  // Set TPM metrics client ID.
  hwsec_foundation::SetTpmMetricsClientID(
      hwsec_foundation::TpmMetricsClientID::kVtpm);

  std::unique_ptr<vtpm::Command> vtpm =
      vtpm::Virtualizer::Create(vtpm::Virtualizer::Profile::kGLinux);

  // Start profiling.
  hwsec_foundation::SetUpProfiling();

  return vtpm::VtpmDaemon(vtpm.get()).Run();
}
