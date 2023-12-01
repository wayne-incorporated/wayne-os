// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM2_ENCRYPTION_H_
#define LIBHWSEC_BACKEND_TPM2_ENCRYPTION_H_

#include <brillo/secure_blob.h>

#include "libhwsec/backend/encryption.h"
#include "libhwsec/backend/tpm2/config.h"
#include "libhwsec/backend/tpm2/key_management.h"
#include "libhwsec/backend/tpm2/trunks_context.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"

namespace hwsec {

class EncryptionTpm2 : public Encryption {
 public:
  EncryptionTpm2(TrunksContext& context,
                 ConfigTpm2& config,
                 KeyManagementTpm2& key_management)
      : context_(context), config_(config), key_management_(key_management) {}

  StatusOr<brillo::Blob> Encrypt(Key key,
                                 const brillo::SecureBlob& plaintext,
                                 EncryptionOptions options) override;
  StatusOr<brillo::SecureBlob> Decrypt(Key key,
                                       const brillo::Blob& ciphertext,
                                       EncryptionOptions options) override;

 private:
  TrunksContext& context_;
  ConfigTpm2& config_;
  KeyManagementTpm2& key_management_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM2_ENCRYPTION_H_
