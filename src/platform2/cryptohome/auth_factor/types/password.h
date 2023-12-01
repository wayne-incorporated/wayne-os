// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_TYPES_PASSWORD_H_
#define CRYPTOHOME_AUTH_FACTOR_TYPES_PASSWORD_H_

#include <memory>
#include <optional>
#include <set>
#include <string>

#include "cryptohome/auth_factor/auth_factor_label_arity.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_factor/types/common.h"
#include "cryptohome/auth_factor/types/interface.h"
#include "cryptohome/auth_intent.h"
#include "cryptohome/credential_verifier.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"
#include "cryptohome/key_objects.h"

namespace cryptohome {

// The block types supported by password factors. The priority is defined based
// on the following:
//   1. Favor TPM ECC as the fastest and best choice.
//   2. If ECC isn't available, prefer binding to PCR.
//   3. If PCR isn't available either, unbound TPM is our last choice.
// If cryptohome is built to allow insecure fallback then we have a fourth
// last resort choice:
//   4. Use the scrypt block, with no TPM
// On boards where this isn't necessary we don't even allow this option. If the
// TPM is not functioning on such a board we prefer to get the error rather than
// falling back to the less secure mechanism.
#if USE_TPM_INSECURE_FALLBACK
using AfDriverWithPasswordBlockTypes =
    AfDriverWithBlockTypes<AuthBlockType::kTpmEcc,
                           AuthBlockType::kTpmBoundToPcr,
                           AuthBlockType::kTpmNotBoundToPcr,
                           AuthBlockType::kScrypt>;
#else
using AfDriverWithPasswordBlockTypes =
    AfDriverWithBlockTypes<AuthBlockType::kTpmEcc,
                           AuthBlockType::kTpmBoundToPcr,
                           AuthBlockType::kTpmNotBoundToPcr>;
#endif

class PasswordAuthFactorDriver final
    : public AfDriverWithType<AuthFactorType::kPassword>,
      public AfDriverWithPasswordBlockTypes,
      public AfDriverSupportedByStorage<AfDriverStorageConfig::kNoChecks,
                                        AfDriverKioskConfig::kNoKiosk>,
      public AfDriverWithMetadata<auth_factor::PasswordMetadata>,
      public AfDriverNoPrepare,
      public AfDriverFullAuthDecrypt,
      public AfDriverNoDelay,
      public AfDriverNoExpiration {
 public:
  PasswordAuthFactorDriver() = default;

 private:
  bool IsSupportedByHardware() const override;
  bool IsLightAuthAllowed(AuthIntent auth_intent) const override;
  std::unique_ptr<CredentialVerifier> CreateCredentialVerifier(
      const std::string& auth_factor_label,
      const AuthInput& auth_input) const override;
  bool NeedsResetSecret() const override;
  bool NeedsRateLimiter() const override;
  AuthFactorLabelArity GetAuthFactorLabelArity() const override;

  std::optional<user_data_auth::AuthFactor> TypedConvertToProto(
      const auth_factor::CommonMetadata& common,
      const auth_factor::PasswordMetadata& typed_metadata) const override;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_TYPES_PASSWORD_H_
