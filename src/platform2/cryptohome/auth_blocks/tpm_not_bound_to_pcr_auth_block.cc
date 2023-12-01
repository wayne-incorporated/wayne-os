// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/tpm_not_bound_to_pcr_auth_block.h"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>

#include <base/check.h>
#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <libhwsec/frontend/cryptohome/frontend.h>
#include <libhwsec/status.h>
#include <libhwsec-foundation/crypto/aes.h>
#include <libhwsec-foundation/crypto/rsa.h>
#include <libhwsec-foundation/crypto/hmac.h>
#include <libhwsec-foundation/crypto/scrypt.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>

#include "cryptohome/auth_blocks/tpm_auth_block_utils.h"
#include "cryptohome/crypto.h"
#include "cryptohome/crypto_error.h"
#include "cryptohome/cryptohome_keys_manager.h"
#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/error/action.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/error/locations.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/vault_keyset.pb.h"

using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec::TPMErrorBase;
using hwsec::TPMRetryAction;
using hwsec_foundation::CreateSecureRandomBlob;
using hwsec_foundation::DeriveSecretsScrypt;
using hwsec_foundation::HmacSha256;
using hwsec_foundation::kAesBlockSize;
using hwsec_foundation::kDefaultAesKeySize;
using hwsec_foundation::kDefaultLegacyPasswordRounds;
using hwsec_foundation::ObscureRsaMessage;
using hwsec_foundation::PasskeyToAesKey;
using hwsec_foundation::UnobscureRsaMessage;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
using hwsec_foundation::status::StatusChain;

namespace cryptohome {

CryptoStatus TpmNotBoundToPcrAuthBlock::IsSupported(Crypto& crypto) {
  DCHECK(crypto.GetHwsec());
  hwsec::StatusOr<bool> is_ready = crypto.GetHwsec()->IsReady();
  if (!is_ready.ok()) {
    return MakeStatus<CryptohomeCryptoError>(
               CRYPTOHOME_ERR_LOC(
                   kLocTpmNotBoundToPcrAuthBlockHwsecReadyErrorInIsSupported),
               ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}))
        .Wrap(TpmAuthBlockUtils::TPMErrorToCryptohomeCryptoError(
            std::move(is_ready).err_status()));
  }
  if (!is_ready.value()) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(
            kLocTpmNotBoundToPcrAuthBlockHwsecNotReadyInIsSupported),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  DCHECK(crypto.cryptohome_keys_manager());
  if (!crypto.cryptohome_keys_manager()->GetKeyLoader(
          CryptohomeKeyType::kRSA)) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(
            kLocTpmNotBoundToPcrAuthBlockNoKeyLoaderInIsSupported),
        ErrorActionSet(
            {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kAuth}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  return OkStatus<CryptohomeCryptoError>();
}

std::unique_ptr<AuthBlock> TpmNotBoundToPcrAuthBlock::New(
    const hwsec::CryptohomeFrontend& hwsec,
    CryptohomeKeysManager& cryptohome_keys_manager) {
  return std::make_unique<TpmNotBoundToPcrAuthBlock>(&hwsec,
                                                     &cryptohome_keys_manager);
}

TpmNotBoundToPcrAuthBlock::TpmNotBoundToPcrAuthBlock(
    const hwsec::CryptohomeFrontend* hwsec,
    CryptohomeKeysManager* cryptohome_keys_manager)
    : AuthBlock(kTpmBackedNonPcrBound),
      hwsec_(hwsec),
      cryptohome_key_loader_(
          cryptohome_keys_manager->GetKeyLoader(CryptohomeKeyType::kRSA)),
      utils_(hwsec, cryptohome_key_loader_) {
  CHECK(hwsec_ != nullptr);
  CHECK(cryptohome_key_loader_ != nullptr);
}

void TpmNotBoundToPcrAuthBlock::Derive(const AuthInput& auth_input,
                                       const AuthBlockState& state,
                                       DeriveCallback callback) {
  if (!auth_input.user_input.has_value()) {
    LOG(ERROR) << "Missing user_input";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocTpmNotBoundToPcrAuthBlockNoUserInputInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }

  const TpmNotBoundToPcrAuthBlockState* tpm_state;
  if (!(tpm_state =
            std::get_if<TpmNotBoundToPcrAuthBlockState>(&state.state))) {
    LOG(ERROR) << "Invalid AuthBlockState";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocTpmNotBoundToPcrAuthBlockInvalidBlockStateInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kAuth}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }

  if (!tpm_state->salt.has_value()) {
    LOG(ERROR) << "Invalid TpmNotBoundToPcrAuthBlockState: missing salt";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocTpmNotBoundToPcrAuthBlockNoSaltInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kAuth,
                            PossibleAction::kDeleteVault}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }
  if (!tpm_state->tpm_key.has_value()) {
    LOG(ERROR) << "Invalid TpmNotBoundToPcrAuthBlockState: missing tpm_key";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocTpmNotBoundToPcrAuthBlockNoTpmKeyInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kAuth,
                            PossibleAction::kDeleteVault}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }
  if (!tpm_state->scrypt_derived.has_value()) {
    LOG(ERROR)
        << "Invalid TpmNotBoundToPcrAuthBlockState: missing scrypt_derived";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocTpmNotBoundToPcrAuthBlockNoScryptDerivedInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kAuth,
                            PossibleAction::kDeleteVault}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }

  brillo::SecureBlob tpm_public_key_hash;
  if (tpm_state->tpm_public_key_hash.has_value()) {
    tpm_public_key_hash = tpm_state->tpm_public_key_hash.value();
  }

  CryptoStatus error = utils_.CheckTPMReadiness(
      tpm_state->tpm_key.has_value(),
      tpm_state->tpm_public_key_hash.has_value(), tpm_public_key_hash);
  if (!error.ok()) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocTpmNotBoundToPcrAuthBlockTpmNotReadyInDerive))
            .Wrap(std::move(error)),
        nullptr, std::nullopt);
    return;
  }
  auto key_blobs = std::make_unique<KeyBlobs>();
  key_blobs->vkk_iv = brillo::SecureBlob(kAesBlockSize);
  key_blobs->vkk_key = brillo::SecureBlob(kDefaultAesKeySize);
  brillo::SecureBlob aes_skey(kDefaultAesKeySize);
  brillo::SecureBlob kdf_skey(kDefaultAesKeySize);

  unsigned int rounds = tpm_state->password_rounds.has_value()
                            ? tpm_state->password_rounds.value()
                            : kDefaultLegacyPasswordRounds;

  // TODO(b/204200132): check if this branch is unnecessary.
  if (tpm_state->scrypt_derived.value()) {
    if (!DeriveSecretsScrypt(
            auth_input.user_input.value(), tpm_state->salt.value(),
            {&aes_skey, &kdf_skey, &key_blobs->vkk_iv.value()})) {
      std::move(callback).Run(
          MakeStatus<CryptohomeCryptoError>(
              CRYPTOHOME_ERR_LOC(
                  kLocTpmNotBoundToPcrAuthBlockScryptDeriveFailedInDecrypt),
              ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
              CryptoError::CE_OTHER_FATAL),
          nullptr, std::nullopt);
      return;
    }
  } else {
    if (!PasskeyToAesKey(auth_input.user_input.value(), tpm_state->salt.value(),
                         rounds, &aes_skey, nullptr)) {
      std::move(callback).Run(
          MakeStatus<CryptohomeCryptoError>(
              CRYPTOHOME_ERR_LOC(
                  kLocTpmNotBoundToPcrAuthBlockPasskeyToAesKeyFailedInDecrypt),
              ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
              CryptoError::CE_OTHER_CRYPTO),
          nullptr, std::nullopt);
      return;
    }
  }

  brillo::SecureBlob unobscure_key;
  if (!UnobscureRsaMessage(tpm_state->tpm_key.value(), aes_skey,
                           &unobscure_key)) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocTpmNotBoundToPcrAuthBlockUnobscureMessageFailedInDecrypt),
            ErrorActionSet({PossibleAction::kReboot,
                            PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_TPM_REBOOT),
        nullptr, std::nullopt);
    return;
  }

  brillo::SecureBlob local_vault_key(auth_input.user_input.value().begin(),
                                     auth_input.user_input.value().end());
  brillo::Blob encrypted_key(unobscure_key.begin(), unobscure_key.end());

  hwsec::Key cryptohome_key = cryptohome_key_loader_->GetCryptohomeKey();
  hwsec::StatusOr<brillo::SecureBlob> result =
      hwsec_->Decrypt(cryptohome_key, encrypted_key);
  if (!result.ok()) {
    ReportCryptohomeError(kDecryptAttemptWithTpmKeyFailed);
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocTpmNotBoundToPcrAuthBlockDecryptFailedInDecrypt),
            ErrorActionSet(PrimaryAction::kIncorrectAuth))
            .Wrap(TpmAuthBlockUtils::TPMErrorToCryptohomeCryptoError(
                std::move(result).err_status())),
        nullptr, std::nullopt);
    return;
  }
  local_vault_key = std::move(*result);

  // TODO(zuan): Handle cases in which all retries failed.

  // TODO(b/204200132): check if this branch is unnecessary.
  if (tpm_state->scrypt_derived.value()) {
    *key_blobs->vkk_key = HmacSha256(kdf_skey, local_vault_key);
  } else {
    if (!PasskeyToAesKey(local_vault_key, tpm_state->salt.value(), rounds,
                         &key_blobs->vkk_key.value(),
                         &key_blobs->vkk_iv.value())) {
      LOG(ERROR) << "Failure converting IVKK to VKK.";
      std::move(callback).Run(
          MakeStatus<CryptohomeCryptoError>(
              CRYPTOHOME_ERR_LOC(
                  kLocTpmNotBoundToPcrAuthBlockVKKConversionFailedInDecrypt),
              ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
              CryptoError::CE_OTHER_FATAL),
          nullptr, std::nullopt);
      return;
    }
  }
  key_blobs->chaps_iv = key_blobs->vkk_iv;

  std::move(callback).Run(OkStatus<CryptohomeCryptoError>(),
                          std::move(key_blobs), std::nullopt);
}

void TpmNotBoundToPcrAuthBlock::Create(const AuthInput& user_input,
                                       CreateCallback callback) {
  if (!user_input.user_input.has_value()) {
    LOG(ERROR) << "Missing user_input";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocTpmNotBoundToPcrAuthBlockNoUserInputInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, nullptr);
    return;
  }

  const brillo::SecureBlob& vault_key = user_input.user_input.value();
  brillo::SecureBlob salt =
      CreateSecureRandomBlob(CRYPTOHOME_DEFAULT_KEY_SALT_SIZE);

  // If the key still isn't loaded, fail the operation.
  if (!cryptohome_key_loader_->HasCryptohomeKey()) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocTpmNotBoundToPcrAuthBlockNoCryptohomeKeyInCreate),
            ErrorActionSet({PossibleAction::kReboot, PossibleAction::kRetry,
                            PossibleAction::kPowerwash}),
            CryptoError::CE_TPM_CRYPTO),
        nullptr, nullptr);
    return;
  }

  const auto local_blob = CreateSecureRandomBlob(kDefaultAesKeySize);
  brillo::SecureBlob tpm_key;
  brillo::SecureBlob aes_skey(kDefaultAesKeySize);
  brillo::SecureBlob kdf_skey(kDefaultAesKeySize);
  brillo::SecureBlob vkk_iv(kAesBlockSize);
  if (!DeriveSecretsScrypt(vault_key, salt, {&aes_skey, &kdf_skey, &vkk_iv})) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocTpmNotBoundToPcrAuthBlockScryptDeriveFailedInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, nullptr);
    return;
  }

  // Encrypt the VKK using the TPM and the user's passkey.  The output is an
  // encrypted blob in tpm_key, which is stored in the serialized vault
  // keyset.
  hwsec::Key cryptohome_key = cryptohome_key_loader_->GetCryptohomeKey();
  hwsec::StatusOr<brillo::Blob> result =
      hwsec_->Encrypt(cryptohome_key, local_blob);
  if (!result.ok()) {
    LOG(ERROR) << "Failed to wrap vkk with creds: " << result.status();
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocTpmNotBoundToPcrAuthBlockEncryptFailedInCreate),
            ErrorActionSet({PossibleAction::kReboot,
                            PossibleAction::kDevCheckUnexpectedState}))
            .Wrap(TpmAuthBlockUtils::TPMErrorToCryptohomeCryptoError(
                std::move(result).err_status())),
        nullptr, nullptr);
    return;
  }
  if (!ObscureRsaMessage(brillo::SecureBlob(result->begin(), result->end()),
                         aes_skey, &tpm_key)) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocTpmNotBoundToPcrAuthBlockObscureMessageFailedInCreate),
            ErrorActionSet({PossibleAction::kReboot,
                            PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_TPM_REBOOT),
        nullptr, nullptr);
    return;
  }

  auto key_blobs = std::make_unique<KeyBlobs>();
  auto auth_block_state = std::make_unique<AuthBlockState>();
  TpmNotBoundToPcrAuthBlockState auth_state;
  // Allow this to fail.  It is not absolutely necessary; it allows us to
  // detect a TPM clear.  If this fails due to a transient issue, then on next
  // successful login, the vault keyset will be re-saved anyway.
  hwsec::StatusOr<brillo::Blob> pub_key_hash =
      hwsec_->GetPubkeyHash(cryptohome_key);
  if (!pub_key_hash.ok()) {
    LOG(ERROR) << "Failed to get tpm public key hash: "
               << pub_key_hash.status();
  } else {
    auth_state.tpm_public_key_hash =
        brillo::SecureBlob(pub_key_hash->begin(), pub_key_hash->end());
  }

  auth_state.scrypt_derived = true;
  auth_state.tpm_key = tpm_key;
  auth_state.salt = std::move(salt);

  // Pass back the vkk_key and vkk_iv so the generic secret wrapping can use it.
  key_blobs->vkk_key = HmacSha256(kdf_skey, local_blob);
  // Note that one might expect the IV to be part of the AuthBlockState. But
  // since it's taken from the scrypt output, it's actually created by the auth
  // block, not used to initialize the auth block.
  key_blobs->vkk_iv = vkk_iv;
  key_blobs->chaps_iv = vkk_iv;

  auth_block_state->state = std::move(auth_state);
  std::move(callback).Run(OkStatus<CryptohomeCryptoError>(),
                          std::move(key_blobs), std::move(auth_block_state));
}

}  // namespace cryptohome
