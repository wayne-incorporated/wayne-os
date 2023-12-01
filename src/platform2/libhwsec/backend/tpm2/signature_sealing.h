// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM2_SIGNATURE_SEALING_H_
#define LIBHWSEC_BACKEND_TPM2_SIGNATURE_SEALING_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <brillo/secure_blob.h>
#include <trunks/trunks_factory.h>

#include "libhwsec/backend/signature_sealing.h"
#include "libhwsec/backend/tpm2/config.h"
#include "libhwsec/backend/tpm2/key_management.h"
#include "libhwsec/backend/tpm2/session_management.h"
#include "libhwsec/backend/tpm2/trunks_context.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/no_default_init.h"

namespace hwsec {

class SignatureSealingTpm2 : public SignatureSealing {
 public:
  SignatureSealingTpm2(TrunksContext& context,
                       ConfigTpm2& config,
                       KeyManagementTpm2& key_management,
                       SessionManagementTpm2& session_management)
      : context_(context),
        config_(config),
        key_management_(key_management),
        session_management_(session_management) {}

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

 private:
  struct InternalChallengeData {
    NoDefault<ChallengeID> challenge_id;
    brillo::Blob srk_wrapped_secret;
    brillo::Blob public_key_spki_der;
    trunks::TPM_ALG_ID scheme;
    trunks::TPM_ALG_ID hash_alg;
    std::unique_ptr<trunks::PolicySession> session;
    std::string session_nonce;
  };

  TrunksContext& context_;
  ConfigTpm2& config_;
  KeyManagementTpm2& key_management_;
  SessionManagementTpm2& session_management_;

  std::optional<InternalChallengeData> current_challenge_data_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM2_SIGNATURE_SEALING_H_
