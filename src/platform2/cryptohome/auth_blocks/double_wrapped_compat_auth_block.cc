// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/double_wrapped_compat_auth_block.h"

#include <memory>
#include <optional>
#include <utility>

#include <base/check.h>
#include <base/logging.h>

#include "cryptohome/auth_blocks/scrypt_auth_block.h"
#include "cryptohome/auth_blocks/tpm_not_bound_to_pcr_auth_block.h"
#include "cryptohome/crypto.h"
#include "cryptohome/cryptohome_keys_manager.h"
#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/error/action.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/error/locations.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"

using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
using hwsec_foundation::status::StatusChain;

namespace cryptohome {

CryptoStatus DoubleWrappedCompatAuthBlock::IsSupported(Crypto& crypto) {
  // Simply delegate to the encapsulated classes. Note that `ScryptAuthBlock`
  // has no `IsSupported()` method - it's always supported for us.
  CryptoStatus tpm_status = TpmNotBoundToPcrAuthBlock::IsSupported(crypto);
  if (!tpm_status.ok()) {
    return MakeStatus<CryptohomeCryptoError>(
               CRYPTOHOME_ERR_LOC(
                   kLocDoubleWrappedAuthBlockTpmBlockErrorInIsSupported))
        .Wrap(std::move(tpm_status));
  }
  return OkStatus<CryptohomeCryptoError>();
}

std::unique_ptr<AuthBlock> DoubleWrappedCompatAuthBlock::New(
    const hwsec::CryptohomeFrontend& hwsec,
    CryptohomeKeysManager& cryptohome_keys_manager) {
  return std::make_unique<DoubleWrappedCompatAuthBlock>(
      &hwsec, &cryptohome_keys_manager);
}

DoubleWrappedCompatAuthBlock::DoubleWrappedCompatAuthBlock(
    const hwsec::CryptohomeFrontend* hwsec,
    CryptohomeKeysManager* cryptohome_keys_manager)
    : AuthBlock(kDoubleWrapped),
      tpm_auth_block_(hwsec, cryptohome_keys_manager) {}

void DoubleWrappedCompatAuthBlock::Create(const AuthInput& user_input,
                                          CreateCallback callback) {
  LOG(FATAL) << "Cannot create a keyset wrapped with both scrypt and TPM.";
  std::move(callback).Run(
      MakeStatus<CryptohomeCryptoError>(
          CRYPTOHOME_ERR_LOC(kLocDoubleWrappedAuthBlockUnsupportedInCreate),
          ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
          CryptoError::CE_OTHER_CRYPTO),
      nullptr, nullptr);
}

void DoubleWrappedCompatAuthBlock::Derive(const AuthInput& user_input,
                                          const AuthBlockState& state,
                                          DeriveCallback callback) {
  const DoubleWrappedCompatAuthBlockState* auth_state;
  if (!(auth_state =
            std::get_if<DoubleWrappedCompatAuthBlockState>(&state.state))) {
    DLOG(FATAL) << "Invalid AuthBlockState";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocDoubleWrappedAuthBlockInvalidBlockStateInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kAuth}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
  }

  AuthBlockState scrypt_state = {.state = auth_state->scrypt_state};
  scrypt_auth_block_.Derive(
      user_input, scrypt_state,
      base::BindOnce(&DoubleWrappedCompatAuthBlock::CreateDeriveAfterScrypt,
                     weak_factory_.GetWeakPtr(), std::move(callback),
                     std::move(user_input), std::move(state)));
}

void DoubleWrappedCompatAuthBlock::CreateDeriveAfterScrypt(
    DeriveCallback callback,
    const AuthInput& user_input,
    const AuthBlockState& state,
    CryptohomeStatus error,
    std::unique_ptr<KeyBlobs> key_blobs,
    std::optional<SuggestedAction> suggested_action) {
  if (error.ok()) {
    std::move(callback).Run(std::move(error), std::move(key_blobs),
                            std::move(suggested_action));
    return;
  }
  const DoubleWrappedCompatAuthBlockState* auth_state;
  if (!(auth_state =
            std::get_if<DoubleWrappedCompatAuthBlockState>(&state.state))) {
    DLOG(FATAL) << "Invalid AuthBlockState";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocDoubleWrappedAuthBlockInvalidBlockStateInAfterScrypt),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kAuth}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
  }

  AuthBlockState tpm_state = {.state = auth_state->tpm_state};
  tpm_auth_block_.Derive(
      user_input, tpm_state,
      base::BindOnce(&DoubleWrappedCompatAuthBlock::CreateDeriveAfterTpm,
                     weak_factory_.GetWeakPtr(), std::move(callback)));
}

void DoubleWrappedCompatAuthBlock::CreateDeriveAfterTpm(
    DeriveCallback callback,
    CryptohomeStatus error,
    std::unique_ptr<KeyBlobs> key_blobs,
    std::optional<SuggestedAction> suggested_action) {
  if (error.ok()) {
    std::move(callback).Run(std::move(error), std::move(key_blobs),
                            std::move(suggested_action));
    return;
  }
  std::move(callback).Run(
      MakeStatus<error::CryptohomeError>(
          CRYPTOHOME_ERR_LOC(kLocDoubleWrappedAuthBlockTpmDeriveFailedInDerive))
          .Wrap(std::move(error)),
      nullptr, std::nullopt);
}

}  // namespace cryptohome
