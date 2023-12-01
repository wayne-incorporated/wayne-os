// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_SEALING_H_
#define LIBHWSEC_BACKEND_TPM1_SEALING_H_

#include <optional>

#include <brillo/secure_blob.h>

#include "libhwsec/backend/sealing.h"
#include "libhwsec/backend/tpm1/config.h"
#include "libhwsec/backend/tpm1/da_mitigation.h"
#include "libhwsec/backend/tpm1/key_management.h"
#include "libhwsec/backend/tpm1/tss_helper.h"
#include "libhwsec/proxy/proxy.h"
#include "libhwsec/status.h"
#include "libhwsec/tss_utils/scoped_tss_type.h"

namespace hwsec {

class SealingTpm1 : public Sealing {
 public:
  SealingTpm1(overalls::Overalls& overalls,
              TssHelper& tss_helper,
              ConfigTpm1& config,
              KeyManagementTpm1& key_management,
              DAMitigationTpm1& da_mitigation)
      : overalls_(overalls),
        tss_helper_(tss_helper),
        config_(config),
        key_management_(key_management),
        da_mitigation_(da_mitigation) {}

  StatusOr<bool> IsSupported() override;
  StatusOr<brillo::Blob> Seal(const OperationPolicySetting& policy,
                              const brillo::SecureBlob& unsealed_data) override;
  StatusOr<std::optional<ScopedKey>> PreloadSealedData(
      const OperationPolicy& policy, const brillo::Blob& sealed_data) override;
  StatusOr<brillo::SecureBlob> Unseal(const OperationPolicy& policy,
                                      const brillo::Blob& sealed_data,
                                      UnsealOptions options) override;

 private:
  StatusOr<ScopedTssKey> GetAuthValueKey(
      const std::optional<brillo::SecureBlob>& auth_value);

  overalls::Overalls& overalls_;
  TssHelper& tss_helper_;
  ConfigTpm1& config_;
  KeyManagementTpm1& key_management_;
  DAMitigationTpm1& da_mitigation_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_SEALING_H_
