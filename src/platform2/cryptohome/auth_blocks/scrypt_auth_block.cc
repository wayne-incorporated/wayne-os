// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/scrypt_auth_block.h"

#include <memory>
#include <utility>
#include <variant>

#include <base/logging.h>
#include <libhwsec-foundation/crypto/aes.h>
#include <libhwsec-foundation/crypto/libscrypt_compat.h>
#include <libhwsec-foundation/crypto/scrypt.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>

#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"

using ::cryptohome::error::CryptohomeCryptoError;
using ::cryptohome::error::ErrorActionSet;
using ::cryptohome::error::PossibleAction;
using ::cryptohome::error::PrimaryAction;
using ::hwsec_foundation::CreateSecureRandomBlob;
using ::hwsec_foundation::kAesBlockSize;
using ::hwsec_foundation::kDefaultAesKeySize;
using ::hwsec_foundation::kDefaultScryptParams;
using ::hwsec_foundation::kLibScryptDerivedKeySize;
using ::hwsec_foundation::kLibScryptSaltSize;
using ::hwsec_foundation::Scrypt;
using ::hwsec_foundation::status::MakeStatus;
using ::hwsec_foundation::status::OkStatus;

namespace cryptohome {

CryptoStatus ScryptAuthBlock::IsSupported(Crypto& crypto) {
  return OkStatus<CryptohomeCryptoError>();
}

std::unique_ptr<AuthBlock> ScryptAuthBlock::New() {
  return std::make_unique<ScryptAuthBlock>();
}

ScryptAuthBlock::ScryptAuthBlock() : AuthBlock(kScryptBacked) {}

ScryptAuthBlock::ScryptAuthBlock(DerivationType derivation_type)
    : AuthBlock(derivation_type) {}

CryptoStatus CreateScryptHelper(const brillo::SecureBlob& input_key,
                                brillo::SecureBlob* out_salt,
                                brillo::SecureBlob* out_derived_key) {
  *out_salt = CreateSecureRandomBlob(kLibScryptSaltSize);

  out_derived_key->resize(kLibScryptDerivedKeySize);
  if (!Scrypt(input_key, *out_salt, kDefaultScryptParams.n_factor,
              kDefaultScryptParams.r_factor, kDefaultScryptParams.p_factor,
              out_derived_key)) {
    LOG(ERROR) << "Scrypt for derived key creation failed.";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocScryptAuthBlockScryptFailedDerivedKeyInCreate),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_SCRYPT_CRYPTO);
  }
  return OkStatus<CryptohomeCryptoError>();
}

void ScryptAuthBlock::Create(const AuthInput& auth_input,
                             CreateCallback callback) {
  const brillo::SecureBlob input_key = auth_input.user_input.value();

  brillo::SecureBlob salt, derived_key;
  CryptoStatus error = CreateScryptHelper(input_key, &salt, &derived_key);
  if (!error.ok()) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocScryptAuthBlockInputKeyFailedInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}))
            .Wrap(std::move(error)),
        nullptr, nullptr);
    return;
  }

  brillo::SecureBlob chaps_salt, derived_scrypt_chaps_key;
  error = CreateScryptHelper(input_key, &chaps_salt, &derived_scrypt_chaps_key);
  if (!error.ok()) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocScryptAuthBlockChapsKeyFailedInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}))
            .Wrap(std::move(error)),
        nullptr, nullptr);
    return;
  }

  brillo::SecureBlob reset_seed_salt, derived_scrypt_reset_seed_key;
  error = CreateScryptHelper(input_key, &reset_seed_salt,
                             &derived_scrypt_reset_seed_key);
  if (!error.ok()) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocScryptAuthBlockResetKeyFailedInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}))
            .Wrap(std::move(error)),
        nullptr, nullptr);
    return;
  }

  auto key_blobs = std::make_unique<KeyBlobs>();
  auto auth_block_state = std::make_unique<AuthBlockState>();

  ScryptAuthBlockState scrypt_state{
      .salt = std::move(salt),
      .chaps_salt = std::move(chaps_salt),
      .reset_seed_salt = std::move(reset_seed_salt),
      .work_factor = kDefaultScryptParams.n_factor,
      .block_size = kDefaultScryptParams.r_factor,
      .parallel_factor = kDefaultScryptParams.p_factor,
  };

  key_blobs->vkk_key = std::move(derived_key);
  key_blobs->scrypt_chaps_key = std::move(derived_scrypt_chaps_key);
  key_blobs->scrypt_reset_seed_key = std::move(derived_scrypt_reset_seed_key);

  auth_block_state->state = std::move(scrypt_state);
  std::move(callback).Run(OkStatus<CryptohomeCryptoError>(),
                          std::move(key_blobs), std::move(auth_block_state));
}

void ScryptAuthBlock::Derive(const AuthInput& auth_input,
                             const AuthBlockState& auth_state,
                             DeriveCallback callback) {
  const ScryptAuthBlockState* state;
  if (!(state = std::get_if<ScryptAuthBlockState>(&auth_state.state))) {
    LOG(ERROR) << "Invalid AuthBlockState";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocScryptAuthBlockInvalidBlockStateInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kAuth}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }

  if (!state->salt.has_value()) {
    LOG(ERROR) << "Invalid ScryptAuthBlockState: missing salt";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocScryptAuthBlockNoSaltInDerive),
            ErrorActionSet({PossibleAction::kAuth, PossibleAction::kReboot,
                            PossibleAction::kDeleteVault}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }

  if (!state->work_factor.has_value() || !state->block_size.has_value() ||
      !state->parallel_factor.has_value()) {
    LOG(ERROR) << "Invalid ScryptAuthBlockState: missing N, R, P factors";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocScryptAuthBlockNofactorsInDerive),
            ErrorActionSet({PossibleAction::kAuth, PossibleAction::kReboot,
                            PossibleAction::kDeleteVault}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }

  const brillo::SecureBlob input_key = auth_input.user_input.value();

  brillo::SecureBlob derived_key(kLibScryptDerivedKeySize);

  if (!Scrypt(input_key, state->salt.value(), state->work_factor.value(),
              state->block_size.value(), state->parallel_factor.value(),
              &derived_key)) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocScryptAuthBlockScryptFailedInDeriveFromSalt),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_SCRYPT_CRYPTO),
        nullptr, std::nullopt);
    return;
  }

  auto key_blobs = std::make_unique<KeyBlobs>();
  std::optional<AuthBlock::SuggestedAction> suggested_action;

  key_blobs->vkk_key = std::move(derived_key);

  if (state->chaps_salt.has_value()) {
    brillo::SecureBlob derived_scrypt_chaps_key(kLibScryptDerivedKeySize);
    if (!Scrypt(input_key, state->chaps_salt.value(),
                state->work_factor.value(), state->block_size.value(),
                state->parallel_factor.value(), &derived_scrypt_chaps_key)) {
      std::move(callback).Run(
          MakeStatus<CryptohomeCryptoError>(
              CRYPTOHOME_ERR_LOC(
                  kLocScryptAuthBlockScryptFailedInDeriveFromChapsSalt),
              ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
              CryptoError::CE_SCRYPT_CRYPTO),
          nullptr, std::nullopt);
      return;
    }
    key_blobs->scrypt_chaps_key = std::move(derived_scrypt_chaps_key);
  }

  if (state->reset_seed_salt.has_value()) {
    brillo::SecureBlob derived_scrypt_reset_seed_key(kLibScryptDerivedKeySize);
    if (!Scrypt(input_key, state->reset_seed_salt.value(),
                state->work_factor.value(), state->block_size.value(),
                state->parallel_factor.value(),
                &derived_scrypt_reset_seed_key)) {
      std::move(callback).Run(
          MakeStatus<CryptohomeCryptoError>(
              CRYPTOHOME_ERR_LOC(
                  kLocScryptAuthBlockScryptFailedInDeriveFromResetSeedSalt),
              ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
              CryptoError::CE_SCRYPT_CRYPTO),
          nullptr, std::nullopt);
      return;
    }
    key_blobs->scrypt_reset_seed_key = std::move(derived_scrypt_reset_seed_key);
  }

  std::move(callback).Run(OkStatus<CryptohomeCryptoError>(),
                          std::move(key_blobs), suggested_action);
}

}  // namespace cryptohome
