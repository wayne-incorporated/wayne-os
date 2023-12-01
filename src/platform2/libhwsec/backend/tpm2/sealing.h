// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM2_SEALING_H_
#define LIBHWSEC_BACKEND_TPM2_SEALING_H_

#include <optional>

#include <brillo/secure_blob.h>

#include "libhwsec/backend/sealing.h"
#include "libhwsec/backend/tpm2/config.h"
#include "libhwsec/backend/tpm2/key_management.h"
#include "libhwsec/backend/tpm2/session_management.h"
#include "libhwsec/backend/tpm2/trunks_context.h"
#include "libhwsec/status.h"

namespace hwsec {

class SealingTpm2 : public Sealing {
 public:
  SealingTpm2(TrunksContext& context,
              ConfigTpm2& config,
              KeyManagementTpm2& key_management,
              SessionManagementTpm2& session_management)
      : context_(context),
        config_(config),
        key_management_(key_management),
        session_management_(session_management) {}

  StatusOr<bool> IsSupported() override;
  StatusOr<brillo::Blob> Seal(const OperationPolicySetting& policy,
                              const brillo::SecureBlob& unsealed_data) override;
  StatusOr<std::optional<ScopedKey>> PreloadSealedData(
      const OperationPolicy& policy, const brillo::Blob& sealed_data) override;
  StatusOr<brillo::SecureBlob> Unseal(const OperationPolicy& policy,
                                      const brillo::Blob& sealed_data,
                                      UnsealOptions options) override;

 private:
  TrunksContext& context_;
  ConfigTpm2& config_;
  KeyManagementTpm2& key_management_;
  SessionManagementTpm2& session_management_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM2_SEALING_H_
