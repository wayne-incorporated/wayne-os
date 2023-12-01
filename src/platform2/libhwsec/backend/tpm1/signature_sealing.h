// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_SIGNATURE_SEALING_H_
#define LIBHWSEC_BACKEND_TPM1_SIGNATURE_SEALING_H_

#include <optional>
#include <vector>

#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>

#include "libhwsec/backend/signature_sealing.h"
#include "libhwsec/backend/tpm1/config.h"
#include "libhwsec/backend/tpm1/key_management.h"
#include "libhwsec/backend/tpm1/random.h"
#include "libhwsec/backend/tpm1/sealing.h"
#include "libhwsec/backend/tpm1/tss_helper.h"
#include "libhwsec/proxy/proxy.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/no_default_init.h"

namespace hwsec {

class SignatureSealingTpm1 : public SignatureSealing {
 public:
  SignatureSealingTpm1(overalls::Overalls& overalls,
                       TssHelper& tss_helper,
                       ConfigTpm1& config,
                       KeyManagementTpm1& key_management,
                       SealingTpm1& sealing,
                       RandomTpm1& random)
      : overalls_(overalls),
        tss_helper_(tss_helper),
        config_(config),
        key_management_(key_management),
        sealing_(sealing),
        random_(random) {}

  StatusOr<SignatureSealedData> Seal(
      const std::vector<OperationPolicySetting>& policies,
      const brillo::SecureBlob& unsealed_data,
      const brillo::Blob& public_key_spki_der,
      const std::vector<Algorithm>& key_algorithms) override;
  StatusOr<ChallengeResult> Challenge(
      const OperationPolicy& policy,
      const SignatureSealedData& sealed_data,
      const brillo::Blob& public_key_spki_der,
      const std::vector<Algorithm>& key_algorithms) override;
  StatusOr<brillo::SecureBlob> Unseal(
      ChallengeID challenge, const brillo::Blob& challenge_response) override;

  const auto& get_current_challenge_data_for_test() const {
    return current_challenge_data_;
  }

 private:
  struct InternalChallengeData {
    NoDefault<ChallengeID> challenge_id;
    OperationPolicy policy;
    brillo::Blob srk_wrapped_cmk;
    brillo::Blob cmk_wrapped_auth_data;
    brillo::Blob pcr_bound_secret;
    brillo::Blob public_key_spki_der;
    brillo::Blob cmk_pubkey;
    brillo::Blob protection_key_pubkey;
    crypto::ScopedRSA migration_destination_rsa;
    brillo::Blob migration_destination_key_pubkey;
  };

  overalls::Overalls& overalls_;
  TssHelper& tss_helper_;
  ConfigTpm1& config_;
  KeyManagementTpm1& key_management_;
  SealingTpm1& sealing_;
  RandomTpm1& random_;

  std::optional<InternalChallengeData> current_challenge_data_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_SIGNATURE_SEALING_H_
