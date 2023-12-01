// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/types/kiosk.h"

#include "cryptohome/auth_factor/auth_factor_label_arity.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"

namespace cryptohome {

bool KioskAuthFactorDriver::IsSupportedByHardware() const {
  return true;
}

bool KioskAuthFactorDriver::NeedsResetSecret() const {
  return false;
}

bool KioskAuthFactorDriver::NeedsRateLimiter() const {
  return false;
}

AuthFactorLabelArity KioskAuthFactorDriver::GetAuthFactorLabelArity() const {
  return AuthFactorLabelArity::kSingle;
}

std::optional<user_data_auth::AuthFactor>
KioskAuthFactorDriver::TypedConvertToProto(
    const auth_factor::CommonMetadata& common,
    const auth_factor::KioskMetadata& typed_metadata) const {
  user_data_auth::AuthFactor proto;
  proto.set_type(user_data_auth::AUTH_FACTOR_TYPE_KIOSK);
  proto.mutable_kiosk_metadata();
  return proto;
}

}  // namespace cryptohome
