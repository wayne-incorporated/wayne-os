// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_ENCRYPTED_REBOOT_VAULT_ENCRYPTED_REBOOT_VAULT_H_
#define CRYPTOHOME_ENCRYPTED_REBOOT_VAULT_ENCRYPTED_REBOOT_VAULT_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <brillo/brillo_export.h>

#include <cryptohome/dircrypto_util.h>
#include <cryptohome/platform.h>
#include <cryptohome/storage/encrypted_container/encrypted_container.h>
#include <cryptohome/storage/keyring/keyring.h>

class EncryptedRebootVault {
 public:
  EncryptedRebootVault();
  ~EncryptedRebootVault() = default;
  // Check if the encrypted reboot vault is setup correctly.
  bool Validate();
  // Unconditionally reset vault.
  bool CreateVault();
  // Setup existing vault; purge on failure.
  bool UnlockVault();
  // Purge vault.
  bool PurgeVault();

 private:
  base::FilePath vault_path_;
  cryptohome::Platform platform_;
  std::unique_ptr<cryptohome::Keyring> keyring_;
  std::unique_ptr<cryptohome::EncryptedContainer> encrypted_container_;
};

#endif  // CRYPTOHOME_ENCRYPTED_REBOOT_VAULT_ENCRYPTED_REBOOT_VAULT_H_
