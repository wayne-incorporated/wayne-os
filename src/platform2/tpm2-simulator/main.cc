// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <base/at_exit.h>
#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "tpm2-simulator/simulator.h"
#include "tpm2-simulator/tpm_executor_version.h"

#if USE_TPM1
#include "tpm2-simulator/tpm_executor_tpm1_impl.h"
#endif

#if USE_TPM2
#include "tpm2-simulator/tpm_executor_tpm2_impl.h"
#endif

#if USE_TI50
#include "tpm2-simulator/tpm_executor_ti50_impl.h"
#endif

using tpm2_simulator::TpmExecutorVersion;

int main(int argc, char* argv[]) {
  DEFINE_bool(sigstop, true, "raise SIGSTOP when TPM initialized");
  DEFINE_string(work_dir, "/mnt/stateful_partition/unencrypted/tpm2-simulator",
                "Daemon data folder");

  base::AtExitManager at_exit;

  brillo::FlagHelper::Init(argc, argv, "TPM2 simulator");
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  if (chdir(FLAGS_work_dir.c_str()) < 0) {
    PLOG(ERROR) << "Failed to change to current directory";
  }

  TpmExecutorVersion version = tpm2_simulator::GetTpmExecutorVersion();

  std::unique_ptr<tpm2_simulator::TpmExecutor> executor;
  switch (version) {
#if USE_TPM1
    case TpmExecutorVersion::kTpm1:
      executor = std::make_unique<tpm2_simulator::TpmExecutorTpm1Impl>();
      break;
#endif

#if USE_TPM2
    case TpmExecutorVersion::kTpm2:
      executor = std::make_unique<tpm2_simulator::TpmExecutorTpm2Impl>();
      break;
#endif

#if USE_TI50
    case TpmExecutorVersion::kTi50:
      executor = std::make_unique<tpm2_simulator::TpmExecutorTi50Impl>();
      break;
#endif

    default:
      NOTREACHED() << "Unknown TPM executor version";
  }

  tpm2_simulator::SimulatorDaemon daemon(executor.get());
  daemon.set_sigstop_on_initialized(FLAGS_sigstop);
  daemon.Run();
}
