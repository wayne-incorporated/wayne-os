// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_ENCRYPTION_H_
#define LIBHWSEC_BACKEND_TPM1_ENCRYPTION_H_

#include <brillo/secure_blob.h>

#include "libhwsec/backend/encryption.h"
#include "libhwsec/backend/tpm1/key_management.h"
#include "libhwsec/backend/tpm1/tss_helper.h"
#include "libhwsec/proxy/proxy.h"
#include "libhwsec/status.h"

namespace hwsec {

class EncryptionTpm1 : public Encryption {
 public:
  EncryptionTpm1(overalls::Overalls& overalls,
                 TssHelper& tss_helper,
                 KeyManagementTpm1& key_management)
      : overalls_(overalls),
        tss_helper_(tss_helper),
        key_management_(key_management) {}

  StatusOr<brillo::Blob> Encrypt(Key key,
                                 const brillo::SecureBlob& plaintext,
                                 EncryptionOptions options) override;
  StatusOr<brillo::SecureBlob> Decrypt(Key key,
                                       const brillo::Blob& ciphertext,
                                       EncryptionOptions options) override;

 private:
  overalls::Overalls& overalls_;
  TssHelper& tss_helper_;
  KeyManagementTpm1& key_management_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_ENCRYPTION_H_
