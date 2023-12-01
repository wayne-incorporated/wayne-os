// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <string>

#include <base/logging.h>
#include <brillo/syslog_logging.h>

#include "tpm_softclear_utils/tpm.h"

int main(int argc, char* argv[]) {
  // All logs go to the system log file.
  int flags = brillo::kLogToSyslog;
  brillo::InitLog(flags);

  std::unique_ptr<tpm_softclear_utils::Tpm> tpm(
      tpm_softclear_utils::Tpm::Create());

  if (!tpm->Initialize()) {
    LOG(ERROR) << "Failed to initialize for soft-clearing TPM.";
    return -1;
  }

  std::optional<std::string> auth_value = tpm->GetAuthForOwnerReset();
  if (!auth_value) {
    LOG(ERROR) << "Unable to soft-clear the TPM: failed to get the auth value.";
    return -1;
  }

  if (!tpm->SoftClearOwner(*auth_value)) {
    LOG(ERROR) << "Unable to soft-clear the TPM.";
    return -1;
  }

  LOG(INFO) << "TPM is soft-cleared.";
  return 0;
}
