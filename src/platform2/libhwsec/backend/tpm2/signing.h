// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM2_SIGNING_H_
#define LIBHWSEC_BACKEND_TPM2_SIGNING_H_

#include <brillo/secure_blob.h>
#include <trunks/tpm_generated.h>

#include "libhwsec/backend/signing.h"
#include "libhwsec/backend/tpm2/config.h"
#include "libhwsec/backend/tpm2/key_management.h"
#include "libhwsec/backend/tpm2/trunks_context.h"
#include "libhwsec/status.h"

namespace hwsec {

class SigningTpm2 : public Signing {
 public:
  SigningTpm2(TrunksContext& context,
              ConfigTpm2& config,
              KeyManagementTpm2& key_management)
      : context_(context), config_(config), key_management_(key_management) {}

  StatusOr<brillo::Blob> Sign(Key key,
                              const brillo::Blob& data,
                              const SigningOptions& options) override;
  StatusOr<brillo::Blob> RawSign(Key key,
                                 const brillo::Blob& data,
                                 const SigningOptions& options) override;
  Status Verify(Key key, const brillo::Blob& signed_data) override;

  // Using the decrypt workaround to sign the data with RSA key.
  StatusOr<brillo::Blob> RawSignRsaWithDecrypt(trunks::TPM_ALG_ID padding,
                                               const KeyTpm2& key_data,
                                               const brillo::Blob& data,
                                               const SigningOptions& options);
  // Get the signing algorithm for |key_data|.
  StatusOr<trunks::TPM_ALG_ID> GetSignAlgorithm(const KeyTpm2& key_data,
                                                const SigningOptions& options);

 private:
  TrunksContext& context_;
  ConfigTpm2& config_;
  KeyManagementTpm2& key_management_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM2_SIGNING_H_
