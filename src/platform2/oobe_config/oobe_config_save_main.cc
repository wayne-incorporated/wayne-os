// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>

#include "oobe_config/metrics/metrics_uma.h"
#include "oobe_config/oobe_config.h"

namespace {

void InitLog() {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  logging::SetLogItems(true /* enable_process_id */,
                       true /* enable_thread_id */, true /* enable_timestamp */,
                       true /* enable_tickcount */);
}

// Pass this to run oobe_config_save with TPM-based encryption. Only do this if
// the target you are rolling back to knows about TPM encryption and is able to
// clear out the TPM rollback space.
constexpr char kWithTpmEncryption[] = "tpm_encrypt";
}  // namespace

int main(int argc, char* argv[]) {
  InitLog();

  oobe_config::MetricsUMA metrics_uma;

  base::CommandLine::Init(argc, argv);
  LOG(INFO) << "Starting oobe_config_save";
  hwsec::FactoryImpl hwsec_factory(hwsec::ThreadingMode::kCurrentThread);
  std::unique_ptr<hwsec::OobeConfigFrontend> hwsec_oobe_config =
      hwsec_factory.GetOobeConfigFrontend();
  oobe_config::OobeConfig oobe_config(hwsec_oobe_config.get());

  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  bool run_tpm_encryption = cl->HasSwitch(kWithTpmEncryption);

  bool save_result = oobe_config.EncryptedRollbackSave(run_tpm_encryption);

  if (!save_result) {
    LOG(ERROR) << "Failed to save rollback data";
    metrics_uma.RecordSaveResult(
        oobe_config::MetricsUMA::RollbackSaveResult::kStage2Failure);
    return 0;
  }

  LOG(INFO) << "Exiting oobe_config_save";
  metrics_uma.RecordSaveResult(
      oobe_config::MetricsUMA::RollbackSaveResult::kSuccess);
  return 0;
}
