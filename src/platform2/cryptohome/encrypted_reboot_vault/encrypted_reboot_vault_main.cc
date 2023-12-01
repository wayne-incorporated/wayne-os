// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/at_exit.h>
#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "cryptohome/encrypted_reboot_vault/encrypted_reboot_vault.h"

int main(int argc, char* argv[]) {
  DEFINE_string(action, "",
                "Select action from {create, unlock, validate, "
                "purge}");

  base::AtExitManager at_exit;
  brillo::FlagHelper::Init(argc, argv, "Chromium OS Reboot Vault Utility");
  brillo::InitLog(brillo::kLogToStderr);

  EncryptedRebootVault vault;

  bool result = false;
  if (FLAGS_action == "create")
    result = vault.CreateVault();
  else if (FLAGS_action == "unlock")
    result = vault.UnlockVault();
  else if (FLAGS_action == "validate")
    result = vault.Validate();
  else if (FLAGS_action == "purge")
    result = vault.PurgeVault();
  else
    LOG(ERROR) << "Invalid action";

  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}
