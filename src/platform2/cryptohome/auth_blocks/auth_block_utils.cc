// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/auth_block_utils.h"

#include <stdint.h>

#include <base/logging.h>

#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/vault_keyset.h"

namespace cryptohome {

namespace {
constexpr AuthBlockFlags auth_block_flags[] = {
    kPinWeaverFlags, kChallengeCredentialFlags, kDoubleWrappedCompatFlags,
    kScryptFlags,    kTpmNotBoundToPcrFlags,    kTpmBoundToPcrFlags,
    kTpmEccFlags};

}  // namespace

bool FlagsToAuthBlockType(int32_t flags, AuthBlockType& out_auth_block_type) {
  for (auto auth_block_flag : auth_block_flags) {
    if ((flags & auth_block_flag.require_flags) ==
            auth_block_flag.require_flags &&
        (flags & auth_block_flag.refuse_flags) == 0) {
      out_auth_block_type = auth_block_flag.auth_block_type;
      return true;
    }
  }
  LOG(ERROR) << "AuthBlock flags doesn't match with a type.";
  return false;
}

bool GetAuthBlockState(const VaultKeyset& vk, AuthBlockState& out_state) {
  AuthBlockType auth_block_type;
  if (!FlagsToAuthBlockType(vk.GetFlags(), auth_block_type)) {
    LOG(ERROR) << "Invalid auth block type";
    return false;
  }

  switch (auth_block_type) {
    case AuthBlockType::kDoubleWrappedCompat:
      return vk.GetDoubleWrappedCompatState(&out_state);

    case AuthBlockType::kTpmEcc:
      return vk.GetTpmEccState(&out_state);

    case AuthBlockType::kTpmBoundToPcr:
      return vk.GetTpmBoundToPcrState(&out_state);

    case AuthBlockType::kTpmNotBoundToPcr:
      return vk.GetTpmNotBoundToPcrState(&out_state);

    case AuthBlockType::kPinWeaver:
      return vk.GetPinWeaverState(&out_state);

    case AuthBlockType::kChallengeCredential:
      return vk.GetSignatureChallengeState(&out_state);

    case AuthBlockType::kScrypt:
      return vk.GetScryptState(&out_state);

    case AuthBlockType::kCryptohomeRecovery:
      LOG(ERROR)
          << "CryptohomeRecovery is not a supported AuthBlockType for now.";
      return false;

    case AuthBlockType::kFingerprint:
      LOG(ERROR) << "Fingerprint is not a supported AuthBlockType.";
      return false;
  }
  LOG(ERROR) << "Invalid auth block type state";
  return false;
}

}  // namespace cryptohome
