// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/cryptohome_recovery_auth_block.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>

#include <base/check.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <brillo/secure_blob.h>
#include <libhwsec/frontend/cryptohome/frontend.h>
#include <libhwsec/status.h>
#include <libhwsec-foundation/crypto/aes.h>
#include <libhwsec-foundation/crypto/hkdf.h>
#include <libhwsec-foundation/crypto/scrypt.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>

#include "cryptohome/auth_blocks/revocation.h"
#include "cryptohome/auth_blocks/tpm_auth_block_utils.h"
#include "cryptohome/crypto.h"
#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/cryptorecovery/recovery_crypto_hsm_cbor_serialization.h"
#include "cryptohome/cryptorecovery/recovery_crypto_impl.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/proto_bindings/rpc.pb.h"
#include "cryptohome/username.h"

using cryptohome::cryptorecovery::HsmPayload;
using cryptohome::cryptorecovery::HsmResponsePlainText;
using cryptohome::cryptorecovery::OnboardingMetadata;
using cryptohome::cryptorecovery::RecoveryCryptoImpl;
using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec_foundation::CreateSecureRandomBlob;
using hwsec_foundation::DeriveSecretsScrypt;
using hwsec_foundation::kAesBlockSize;
using hwsec_foundation::kDefaultAesKeySize;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
using hwsec_foundation::status::StatusChain;

namespace cryptohome {

namespace {

void LogDeriveFailure(CryptoError error) {
  // Note: the error format should match `cryptohome_recovery_failure` in
  // crash-reporter/anomaly_detector.cc
  LOG(ERROR) << "Cryptohome Recovery Derive failure, error = " << error;
}

}  // namespace

CryptoStatus CryptohomeRecoveryAuthBlock::IsSupported(Crypto& crypto) {
  DCHECK(crypto.GetHwsec());
  hwsec::StatusOr<bool> is_ready = crypto.GetHwsec()->IsReady();
  if (!is_ready.ok()) {
    return MakeStatus<CryptohomeCryptoError>(
               CRYPTOHOME_ERR_LOC(
                   kLocRecoveryAuthBlockHwsecReadyErrorInIsSupported),
               ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}))
        .Wrap(TpmAuthBlockUtils::TPMErrorToCryptohomeCryptoError(
            std::move(is_ready).err_status()));
  }
  if (!is_ready.value()) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocRecoveryAuthBlockHwsecNotReadyInIsSupported),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  if (!crypto.GetRecoveryCrypto()) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocRecoveryAuthBlockHwsecNoCryptoInIsSupported),
        ErrorActionSet(
            {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kAuth}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  return OkStatus<CryptohomeCryptoError>();
}

std::unique_ptr<AuthBlock> CryptohomeRecoveryAuthBlock::New(
    Platform& platform,
    const hwsec::CryptohomeFrontend& hwsec,
    const hwsec::RecoveryCryptoFrontend& recovery_hwsec,
    LECredentialManager* le_manager) {
  return std::make_unique<CryptohomeRecoveryAuthBlock>(&hwsec, &recovery_hwsec,
                                                       le_manager, &platform);
}

CryptohomeRecoveryAuthBlock::CryptohomeRecoveryAuthBlock(
    const hwsec::CryptohomeFrontend* hwsec,
    const hwsec::RecoveryCryptoFrontend* recovery_hwsec,
    Platform* platform)
    : CryptohomeRecoveryAuthBlock(hwsec, recovery_hwsec, nullptr, platform) {}

CryptohomeRecoveryAuthBlock::CryptohomeRecoveryAuthBlock(
    const hwsec::CryptohomeFrontend* hwsec,
    const hwsec::RecoveryCryptoFrontend* recovery_hwsec,
    LECredentialManager* le_manager,
    Platform* platform)
    : AuthBlock(/*derivation_type=*/kCryptohomeRecovery),
      hwsec_(hwsec),
      recovery_hwsec_(recovery_hwsec),
      le_manager_(le_manager),
      platform_(platform) {
  DCHECK(hwsec_);
  DCHECK(recovery_hwsec_);
  DCHECK(platform_);
}

void CryptohomeRecoveryAuthBlock::Create(const AuthInput& auth_input,
                                         CreateCallback callback) {
  DCHECK(auth_input.cryptohome_recovery_auth_input.has_value());
  auto cryptohome_recovery_auth_input =
      auth_input.cryptohome_recovery_auth_input.value();
  DCHECK(cryptohome_recovery_auth_input.mediator_pub_key.has_value());
  DCHECK(!cryptohome_recovery_auth_input.user_gaia_id.empty());
  DCHECK(!cryptohome_recovery_auth_input.device_user_id.empty());

  if (!auth_input.obfuscated_username.has_value()) {
    LOG(ERROR) << "Missing obfuscated_username";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocRecoveryAuthBlockNoUsernameInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, nullptr);
    return;
  }
  const brillo::SecureBlob& mediator_pub_key =
      cryptohome_recovery_auth_input.mediator_pub_key.value();
  std::unique_ptr<RecoveryCryptoImpl> recovery =
      RecoveryCryptoImpl::Create(recovery_hwsec_, platform_);
  if (!recovery) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocRecoveryAuthBlockCantCreateRecoveryInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kReboot, PossibleAction::kAuth}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, nullptr);
    return;
  }

  // Generates HSM payload that would be persisted on a chromebook.
  OnboardingMetadata onboarding_metadata;
  AccountIdentifier account_id;
  account_id.set_email(*auth_input.username);
  if (!recovery->GenerateRecoveryId(account_id)) {
    LOG(ERROR) << "Unable to generate a new recovery_id";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocCryptohomeRecoveryAuthBlockNoRecoveryIdInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kReboot}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, nullptr);
    return;
  }
  std::string recovery_id = recovery->LoadStoredRecoveryId(account_id);
  if (recovery_id.empty()) {
    LOG(ERROR) << "Unable to load persisted recovery_id";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocCryptohomeRecoveryAuthBlockFailedRecoveryIdReadInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kReboot}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, nullptr);
    return;
  }
  recovery->GenerateOnboardingMetadata(
      cryptohome_recovery_auth_input.user_gaia_id,
      cryptohome_recovery_auth_input.device_user_id, recovery_id,
      &onboarding_metadata);
  cryptorecovery::GenerateHsmPayloadRequest generate_hsm_payload_request(
      {.mediator_pub_key = mediator_pub_key,
       .onboarding_metadata = onboarding_metadata,
       .obfuscated_username = auth_input.obfuscated_username.value()});
  cryptorecovery::GenerateHsmPayloadResponse generate_hsm_payload_response;
  if (!recovery->GenerateHsmPayload(generate_hsm_payload_request,
                                    &generate_hsm_payload_response)) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocRecoveryAuthBlockGenerateHSMPayloadFailedInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kReboot, PossibleAction::kAuth}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, nullptr);
    return;
  }

  auto key_blobs = std::make_unique<KeyBlobs>();
  auto auth_block_state = std::make_unique<AuthBlockState>();
  // Generate wrapped keys from the recovery key.
  key_blobs->vkk_key = generate_hsm_payload_response.recovery_key;

  // Save generated data in auth_block_state.
  CryptohomeRecoveryAuthBlockState auth_state;

  brillo::SecureBlob hsm_payload_cbor;
  if (!SerializeHsmPayloadToCbor(generate_hsm_payload_response.hsm_payload,
                                 &hsm_payload_cbor)) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocRecoveryAuthBlockCborConvFailedInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kReboot, PossibleAction::kAuth}),
            CryptoError::CE_OTHER_FATAL),
        nullptr, nullptr);
    return;
  }
  auth_state.hsm_payload = hsm_payload_cbor;

  auth_state.encrypted_destination_share =
      generate_hsm_payload_response.encrypted_destination_share;
  auth_state.extended_pcr_bound_destination_share =
      generate_hsm_payload_response.extended_pcr_bound_destination_share;
  auth_state.encrypted_channel_priv_key =
      generate_hsm_payload_response.encrypted_channel_priv_key;
  auth_state.channel_pub_key = generate_hsm_payload_response.channel_pub_key;
  auth_state.encrypted_rsa_priv_key =
      generate_hsm_payload_response.encrypted_rsa_priv_key;
  auth_block_state->state = std::move(auth_state);

  if (revocation::IsRevocationSupported(hwsec_)) {
    DCHECK(le_manager_);
    RevocationState revocation_state;
    CryptoStatus result =
        revocation::Create(le_manager_, &revocation_state, key_blobs.get());
    if (!result.ok()) {
      std::move(callback).Run(
          MakeStatus<CryptohomeCryptoError>(
              CRYPTOHOME_ERR_LOC(
                  kLocRecoveryAuthBlockRevocationCreateFailedInCreate))
              .Wrap(std::move(result)),
          nullptr, nullptr);
      return;
    }
    auth_block_state->revocation_state = revocation_state;
  }

  std::move(callback).Run(OkStatus<CryptohomeCryptoError>(),
                          std::move(key_blobs), std::move(auth_block_state));
}

void CryptohomeRecoveryAuthBlock::Derive(const AuthInput& auth_input,
                                         const AuthBlockState& state,
                                         DeriveCallback callback) {
  const CryptohomeRecoveryAuthBlockState* auth_state;
  if (!(auth_state =
            std::get_if<CryptohomeRecoveryAuthBlockState>(&state.state))) {
    DLOG(FATAL) << "Invalid AuthBlockState";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocRecoveryAuthBlockInvalidBlockStateInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kAuth}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }

  if (!auth_input.obfuscated_username.has_value()) {
    LOG(ERROR) << "Missing obfuscated_username";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocRecoveryAuthBlockNoUsernameInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }
  const ObfuscatedUsername& obfuscated_username =
      auth_input.obfuscated_username.value();

  if (!auth_input.cryptohome_recovery_auth_input.has_value()) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocRecoveryAuthBlockNoAuthInputInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }
  auto cryptohome_recovery_auth_input =
      auth_input.cryptohome_recovery_auth_input.value();
  if (!cryptohome_recovery_auth_input.epoch_response.has_value()) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocRecoveryAuthBlockNoEpochResponseInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }
  brillo::SecureBlob serialized_epoch_response =
      cryptohome_recovery_auth_input.epoch_response.value();
  if (!cryptohome_recovery_auth_input.ephemeral_pub_key.has_value()) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocRecoveryAuthBlockNoEphPubKeyInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }
  const brillo::SecureBlob& ephemeral_pub_key =
      cryptohome_recovery_auth_input.ephemeral_pub_key.value();
  if (!cryptohome_recovery_auth_input.recovery_response.has_value()) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocRecoveryAuthBlockNoRecoveryResponseInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }
  brillo::SecureBlob serialized_response_proto =
      cryptohome_recovery_auth_input.recovery_response.value();
  if (!cryptohome_recovery_auth_input.ledger_public_key.has_value()) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocRecoveryAuthBlockNoLedgerPubKeyInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }

  cryptorecovery::CryptoRecoveryEpochResponse epoch_response;
  if (!epoch_response.ParseFromString(serialized_epoch_response.to_string())) {
    LOG(ERROR) << "Failed to parse CryptoRecoveryEpochResponse";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocRecoveryAuthBlockCantParseEpochResponseInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }
  cryptorecovery::CryptoRecoveryRpcResponse response_proto;
  if (!response_proto.ParseFromString(serialized_response_proto.to_string())) {
    LOG(ERROR) << "Failed to parse CryptoRecoveryRpcResponse";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocRecoveryAuthBlockCantParseResponseInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }

  std::unique_ptr<RecoveryCryptoImpl> recovery =
      RecoveryCryptoImpl::Create(recovery_hwsec_, platform_);
  if (!recovery) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocRecoveryAuthBlockCantCreateRecoveryInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kReboot, PossibleAction::kAuth}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }
  HsmResponsePlainText response_plain_text;
  CryptoStatus decrypt_result = recovery->DecryptResponsePayload(
      cryptorecovery::DecryptResponsePayloadRequest(
          {.encrypted_channel_priv_key = auth_state->encrypted_channel_priv_key,
           .epoch_response = epoch_response,
           .recovery_response_proto = response_proto,
           .obfuscated_username = obfuscated_username,
           .ledger_info =
               {.name = cryptohome_recovery_auth_input.ledger_name,
                .key_hash = cryptohome_recovery_auth_input.ledger_key_hash,
                .public_key =
                    cryptohome_recovery_auth_input.ledger_public_key.value()}}),
      &response_plain_text);
  if (!decrypt_result.ok()) {
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocRecoveryAuthBlockDecryptFailedInDerive))
            .Wrap(std::move(decrypt_result)),
        nullptr, std::nullopt);
    return;
  }

  brillo::SecureBlob recovery_key;
  if (!recovery->RecoverDestination(
          cryptorecovery::RecoverDestinationRequest(
              {.dealer_pub_key = response_plain_text.dealer_pub_key,
               .key_auth_value = response_plain_text.key_auth_value,
               .encrypted_destination_share =
                   auth_state->encrypted_destination_share,
               .extended_pcr_bound_destination_share =
                   auth_state->extended_pcr_bound_destination_share,
               .ephemeral_pub_key = ephemeral_pub_key,
               .mediated_publisher_pub_key = response_plain_text.mediated_point,
               .obfuscated_username = obfuscated_username}),
          &recovery_key)) {
    LogDeriveFailure(CryptoError::CE_OTHER_CRYPTO);
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocRecoveryAuthBlockRecoveryFailedInDerive),
            ErrorActionSet(PrimaryAction::kIncorrectAuth),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }
  auto key_blobs = std::make_unique<KeyBlobs>();
  // Generate wrapped keys from the recovery key.
  key_blobs->vkk_key = recovery_key;

  if (state.revocation_state.has_value()) {
    DCHECK(revocation::IsRevocationSupported(hwsec_));
    DCHECK(le_manager_);
    CryptoStatus result = revocation::Derive(
        le_manager_, state.revocation_state.value(), key_blobs.get());
    if (!result.ok()) {
      LogDeriveFailure(result->local_crypto_error());
      std::move(callback).Run(
          MakeStatus<CryptohomeCryptoError>(
              CRYPTOHOME_ERR_LOC(
                  kLocRecoveryAuthBlockRevocationDeriveFailedInDerive))
              .Wrap(std::move(result)),
          nullptr, std::nullopt);
      return;
    }
  }

  std::move(callback).Run(OkStatus<CryptohomeCryptoError>(),
                          std::move(key_blobs), std::nullopt);
}

void CryptohomeRecoveryAuthBlock::PrepareForRemoval(const AuthBlockState& state,
                                                    StatusCallback callback) {
  CryptoStatus crypto_err = PrepareForRemovalInternal(state);
  if (!crypto_err.ok()) {
    LOG(WARNING) << "PrepareForRemoval failed for cryptohome recovery auth "
                    "block. Error: "
                 << crypto_err;
    ReportPrepareForRemovalResult(AuthBlockType::kCryptohomeRecovery,
                                  crypto_err->local_crypto_error());
    // This error is not fatal, proceed to deleting from disk.
  } else {
    ReportPrepareForRemovalResult(AuthBlockType::kCryptohomeRecovery,
                                  CryptoError::CE_NONE);
  }

  std::move(callback).Run(OkStatus<CryptohomeCryptoError>());
}

CryptoStatus CryptohomeRecoveryAuthBlock::PrepareForRemovalInternal(
    const AuthBlockState& state) {
  if (!std::holds_alternative<CryptohomeRecoveryAuthBlockState>(state.state)) {
    NOTREACHED() << "Invalid AuthBlockState";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(
            kLocRecoveryAuthBlockInvalidStateInPrepareForRemoval),
        ErrorActionSet(
            {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kAuth}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  if (!state.revocation_state.has_value()) {
    // No revocation state means that credentials revocation wasn't used in
    // Create(), so there is nothing to do here. This happens when
    // `revocation::IsRevocationSupported()` is `false`.
    return OkStatus<CryptohomeCryptoError>();
  }

  if (!revocation::IsRevocationSupported(hwsec_)) {
    LOG(ERROR)
        << "Revocation is not supported during recovery auth block removal";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(
            kLocRecoveryAuthBlockNoRevocationInPrepareForRemoval),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                        PossibleAction::kReboot}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  if (!le_manager_) {
    LOG(ERROR) << "No LE manager during recovery auth block removal";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocRecoveryAuthBlockNoLEManagerInPrepareForRemoval),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                        PossibleAction::kReboot}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  CryptoStatus result =
      revocation::Revoke(AuthBlockType::kCryptohomeRecovery, le_manager_,
                         state.revocation_state.value());
  if (!result.ok()) {
    return MakeStatus<CryptohomeCryptoError>(
               CRYPTOHOME_ERR_LOC(
                   kLocRecoveryAuthBlockRevocationFailedInPrepareForRemoval))
        .Wrap(std::move(result));
  }
  return OkStatus<CryptohomeCryptoError>();
}

}  // namespace cryptohome
