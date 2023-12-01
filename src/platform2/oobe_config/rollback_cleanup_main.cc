// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>
#include <libhwsec/factory/factory_impl.h>
#include <libhwsec/frontend/oobe_config/frontend.h>

#include "oobe_config/filesystem/file_handler.h"

namespace {

void InitLog() {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  logging::SetLogItems(/*enable_process_id=*/true, /*enable_thread_id=*/true,
                       /*enable_timestamp=*/true, /*enable_tickcount=*/true);
}

void ZeroTpmSpaceIfExists() {
  auto hwsec_factory_ = std::make_unique<hwsec::FactoryImpl>();
  std::unique_ptr<hwsec::OobeConfigFrontend> hwsec_ =
      hwsec_factory_->GetOobeConfigFrontend();

  hwsec::Status space_ready = hwsec_->IsRollbackSpaceReady();
  if (space_ready.ok()) {
    hwsec::Status space_reset = hwsec_->ResetRollbackSpace();
    if (!space_reset.ok()) {
      LOG(ERROR) << space_reset.status();
      // TODO(b/262235959): Report failure to reset rollback space.
    }
  } else if (space_ready->ToTPMRetryAction() ==
             hwsec::TPMRetryAction::kSpaceNotFound) {
    // Not finding space is expected, log as informational.
    LOG(INFO) << space_ready.status();
  } else {
    LOG(ERROR) << space_ready.status();
  }
}

}  // namespace

// Cleans up after a rollback happened by deleting any remaining files and
// zero'ing the TPM space if it exists. Should be called once the device is
// owned.
int main(int argc, char* argv[]) {
  InitLog();
  oobe_config::FileHandler file_handler;
  file_handler.RemoveRestorePath();
  file_handler.RemoveOpensslEncryptedRollbackData();
  file_handler.RemoveTpmEncryptedRollbackData();
  ZeroTpmSpaceIfExists();
  return 0;
}
