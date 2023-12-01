// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_TYPES_SMART_CARD_H_
#define CRYPTOHOME_AUTH_FACTOR_TYPES_SMART_CARD_H_

#include <memory>
#include <optional>
#include <set>
#include <string>

#include "cryptohome/auth_blocks/auth_block_type.h"
#include "cryptohome/auth_factor/auth_factor_label_arity.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_factor/types/common.h"
#include "cryptohome/auth_factor/types/interface.h"
#include "cryptohome/auth_intent.h"
#include "cryptohome/challenge_credentials/challenge_credentials_helper.h"
#include "cryptohome/credential_verifier.h"
#include "cryptohome/crypto.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"
#include "cryptohome/key_challenge_service_factory.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/util/async_init.h"

namespace cryptohome {

class SmartCardAuthFactorDriver final
    : public AfDriverWithType<AuthFactorType::kSmartCard>,
      public AfDriverWithBlockTypes<AuthBlockType::kChallengeCredential>,
      public AfDriverSupportedByStorage<AfDriverStorageConfig::kNoChecks,
                                        AfDriverKioskConfig::kNoKiosk>,
      public AfDriverWithMetadata<auth_factor::SmartCardMetadata>,
      public AfDriverNoPrepare,
      public AfDriverFullAuthDecrypt,
      public AfDriverNoDelay,
      public AfDriverNoExpiration {
 public:
  SmartCardAuthFactorDriver(
      Crypto* crypto,
      AsyncInitPtr<ChallengeCredentialsHelper> challenge_credentials_helper,
      KeyChallengeServiceFactory* key_challenge_service_factory)
      : crypto_(crypto),
        challenge_credentials_helper_(challenge_credentials_helper),
        key_challenge_service_factory_(key_challenge_service_factory) {}

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
      const auth_factor::SmartCardMetadata& typed_metadata) const override;

  Crypto* crypto_;
  AsyncInitPtr<ChallengeCredentialsHelper> challenge_credentials_helper_;
  KeyChallengeServiceFactory* key_challenge_service_factory_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_TYPES_SMART_CARD_H_
