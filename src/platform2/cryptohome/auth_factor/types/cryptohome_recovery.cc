// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/types/cryptohome_recovery.h"

#include "cryptohome/auth_blocks/cryptohome_recovery_auth_block.h"
#include "cryptohome/auth_factor/auth_factor_label_arity.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"

namespace cryptohome {

bool CryptohomeRecoveryAuthFactorDriver::IsSupportedByHardware() const {
  return CryptohomeRecoveryAuthBlock::IsSupported(*crypto_).ok();
}

bool CryptohomeRecoveryAuthFactorDriver::NeedsResetSecret() const {
  return false;
}

bool CryptohomeRecoveryAuthFactorDriver::NeedsRateLimiter() const {
  return false;
}

AuthFactorLabelArity
CryptohomeRecoveryAuthFactorDriver::GetAuthFactorLabelArity() const {
  return AuthFactorLabelArity::kSingle;
}

std::optional<user_data_auth::AuthFactor>
CryptohomeRecoveryAuthFactorDriver::TypedConvertToProto(
    const auth_factor::CommonMetadata& common,
    const auth_factor::CryptohomeRecoveryMetadata& typed_metadata) const {
  user_data_auth::AuthFactor proto;
  proto.set_type(user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY);
  // TODO(b/232896212): There's no metadata for recovery auth factor
  // currently.
  proto.mutable_cryptohome_recovery_metadata();
  return proto;
}

}  // namespace cryptohome
