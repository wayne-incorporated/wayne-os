// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM2_DERIVING_H_
#define LIBHWSEC_BACKEND_TPM2_DERIVING_H_

#include <brillo/secure_blob.h>

#include "libhwsec/backend/deriving.h"
#include "libhwsec/backend/tpm2/config.h"
#include "libhwsec/backend/tpm2/key_management.h"
#include "libhwsec/backend/tpm2/session_management.h"
#include "libhwsec/backend/tpm2/trunks_context.h"
#include "libhwsec/status.h"

namespace hwsec {

class DerivingTpm2 : public Deriving {
 public:
  DerivingTpm2(TrunksContext& context,
               ConfigTpm2& config,
               KeyManagementTpm2& key_management)
      : context_(context), config_(config), key_management_(key_management) {}

  StatusOr<brillo::Blob> Derive(Key key, const brillo::Blob& blob) override;
  StatusOr<brillo::SecureBlob> SecureDerive(
      Key key, const brillo::SecureBlob& blob) override;

 private:
  StatusOr<brillo::SecureBlob> DeriveRsaKey(const KeyTpm2& key_data,
                                            const brillo::SecureBlob& blob);
  StatusOr<brillo::SecureBlob> DeriveEccKey(const KeyTpm2& key_data,
                                            const brillo::SecureBlob& blob);

  TrunksContext& context_;
  ConfigTpm2& config_;
  KeyManagementTpm2& key_management_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM2_DERIVING_H_
