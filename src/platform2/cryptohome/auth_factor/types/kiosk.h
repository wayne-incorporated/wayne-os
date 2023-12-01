// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_TYPES_KIOSK_H_
#define CRYPTOHOME_AUTH_FACTOR_TYPES_KIOSK_H_

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
#include "cryptohome/auth_factor/types/password.h"
#include "cryptohome/auth_intent.h"
#include "cryptohome/credential_verifier.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"
#include "cryptohome/key_objects.h"

namespace cryptohome {

class KioskAuthFactorDriver final
    : public AfDriverWithType<AuthFactorType::kKiosk>,
      public AfDriverWithPasswordBlockTypes,
      public AfDriverSupportedByStorage<AfDriverStorageConfig::kNoChecks,
                                        AfDriverKioskConfig::kOnlyKiosk>,
      public AfDriverWithMetadata<auth_factor::KioskMetadata>,
      public AfDriverNoPrepare,
      public AfDriverFullAuthDecrypt,
      public AfDriverNoCredentialVerifier,
      public AfDriverNoDelay,
      public AfDriverNoExpiration {
 public:
  KioskAuthFactorDriver() = default;

 private:
  bool IsSupportedByHardware() const override;
  bool NeedsResetSecret() const override;
  bool NeedsRateLimiter() const override;
  AuthFactorLabelArity GetAuthFactorLabelArity() const override;

  std::optional<user_data_auth::AuthFactor> TypedConvertToProto(
      const auth_factor::CommonMetadata& common,
      const auth_factor::KioskMetadata& typed_metadata) const override;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_TYPES_KIOSK_H_
