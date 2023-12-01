// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_OOBE_CONFIG_FRONTEND_H_
#define LIBHWSEC_FRONTEND_OOBE_CONFIG_FRONTEND_H_

#include <optional>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/frontend/frontend.h"
#include "libhwsec/status.h"

namespace hwsec {

// The OobeConfig encrypts and decrypts data using sealed_storage library. Data
// is bound to:
// 1. The current boot mode configuration. That means it cannot be decrypted
//    after switching from or to dev mode.
// 2. A secret that is stored in Space::kEnterpriseRollback. The secret is read
//    for decryption and can be wiped from the space with `ResetRollbackSpace`.
// 3. The TPM's endorsement hierarchy. That means data can only be decrypted on
//    the same TPM. Endorsement hierarchy is not cleared on TPM clear.

class OobeConfigFrontend : public Frontend {
 public:
  ~OobeConfigFrontend() override = default;

  // Is the rollback space is ready to use or not.
  virtual Status IsRollbackSpaceReady() const = 0;

  // Reset the rollback space and making any previously encrypted data
  // undecryptable.
  virtual Status ResetRollbackSpace() const = 0;

  // Encrypts given data and ties it to the current boot mode configuration and
  // a secret it generates and stores in Space::kEnterpriseRollback.
  virtual StatusOr<brillo::Blob> Encrypt(
      const brillo::SecureBlob& plain_data) const = 0;

  // Attempts to decrypt data with the current content of
  // Space::kEnterpriseRollback. Note that this does NOT clear the content in
  // Space::kEnterpriseRollback. This needs to be done with
  // `ResetRollbackSpace`.
  virtual StatusOr<brillo::SecureBlob> Decrypt(
      const brillo::Blob& encrypted_data) const = 0;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_OOBE_CONFIG_FRONTEND_H_
