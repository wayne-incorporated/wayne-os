// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/auth_block_utility_impl.h"

#include <stdint.h>

#include <memory>
#include <optional>
#include <set>
#include <utility>
#include <variant>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <brillo/cryptohome.h>
#include <chromeos/constants/cryptohome.h>
#include <libhwsec-foundation/status/status_chain_or.h>

#include "cryptohome/auth_blocks/auth_block.h"
#include "cryptohome/auth_blocks/auth_block_type.h"
#include "cryptohome/auth_blocks/auth_block_utils.h"
#include "cryptohome/auth_blocks/challenge_credential_auth_block.h"
#include "cryptohome/auth_blocks/cryptohome_recovery_auth_block.h"
#include "cryptohome/auth_blocks/double_wrapped_compat_auth_block.h"
#include "cryptohome/auth_blocks/fingerprint_auth_block.h"
#include "cryptohome/auth_blocks/generic.h"
#include "cryptohome/auth_blocks/pin_weaver_auth_block.h"
#include "cryptohome/auth_blocks/scrypt_auth_block.h"
#include "cryptohome/auth_blocks/tpm_bound_to_pcr_auth_block.h"
#include "cryptohome/auth_blocks/tpm_ecc_auth_block.h"
#include "cryptohome/auth_blocks/tpm_not_bound_to_pcr_auth_block.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/crypto.h"
#include "cryptohome/crypto_error.h"
#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/cryptorecovery/recovery_crypto.h"
#include "cryptohome/cryptorecovery/recovery_crypto_hsm_cbor_serialization.h"
#include "cryptohome/cryptorecovery/recovery_crypto_impl.h"
#include "cryptohome/cryptorecovery/recovery_crypto_util.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/error/utilities.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/keyset_management.h"
#include "cryptohome/vault_keyset.h"

using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::CryptohomeError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
using hwsec_foundation::status::StatusChain;

namespace cryptohome {

AuthBlockUtilityImpl::AuthBlockUtilityImpl(
    KeysetManagement* keyset_management,
    Crypto* crypto,
    Platform* platform,
    AsyncInitFeatures* features,
    AsyncInitPtr<ChallengeCredentialsHelper> challenge_credentials_helper,
    KeyChallengeServiceFactory* key_challenge_service_factory,
    AsyncInitPtr<BiometricsAuthBlockService> bio_service)
    : keyset_management_(keyset_management),
      crypto_(crypto),
      platform_(platform),
      features_(features),
      challenge_credentials_helper_(challenge_credentials_helper),
      key_challenge_service_factory_(key_challenge_service_factory),
      bio_service_(bio_service) {
  DCHECK(keyset_management_);
  DCHECK(crypto_);
  DCHECK(platform_);
  DCHECK(features_);
}

bool AuthBlockUtilityImpl::GetLockedToSingleUser() const {
  return platform_->FileExists(base::FilePath(kLockedToSingleUserFile));
}

void AuthBlockUtilityImpl::CreateKeyBlobsWithAuthBlock(
    AuthBlockType auth_block_type,
    const AuthInput& auth_input,
    AuthBlock::CreateCallback create_callback) {
  CryptoStatusOr<std::unique_ptr<AuthBlock>> auth_block =
      GetAuthBlockWithType(auth_block_type, auth_input);
  if (!auth_block.ok()) {
    LOG(ERROR) << "Failed to retrieve auth block.";
    std::move(create_callback)
        .Run(MakeStatus<CryptohomeCryptoError>(
                 CRYPTOHOME_ERR_LOC(
                     kLocAuthBlockUtilNoAuthBlockInCreateKeyBlobsAsync))
                 .Wrap(std::move(auth_block).err_status()),
             nullptr, nullptr);
    return;
  }
  ReportCreateAuthBlock(auth_block_type);

  // This lambda functions to keep the auth_block reference valid until
  // the results are returned through create_callback.
  AuthBlock* auth_block_ptr = auth_block->get();
  auto managed_callback = base::BindOnce(
      [](std::unique_ptr<AuthBlock> owned_auth_block,
         AuthBlock::CreateCallback callback, CryptohomeStatus error,
         std::unique_ptr<KeyBlobs> key_blobs,
         std::unique_ptr<AuthBlockState> auth_block_state) {
        std::move(callback).Run(std::move(error), std::move(key_blobs),
                                std::move(auth_block_state));
      },
      std::move(auth_block.value()), std::move(create_callback));
  auth_block_ptr->Create(auth_input, std::move(managed_callback));
}

void AuthBlockUtilityImpl::DeriveKeyBlobsWithAuthBlock(
    AuthBlockType auth_block_type,
    const AuthInput& auth_input,
    const AuthBlockState& auth_state,
    AuthBlock::DeriveCallback derive_callback) {
  CryptoStatusOr<std::unique_ptr<AuthBlock>> auth_block =
      GetAuthBlockWithType(auth_block_type, auth_input);
  if (!auth_block.ok()) {
    LOG(ERROR) << "Failed to retrieve auth block.";
    std::move(derive_callback)
        .Run(MakeStatus<CryptohomeCryptoError>(
                 CRYPTOHOME_ERR_LOC(
                     kLocAuthBlockUtilNoAuthBlockInDeriveKeyBlobsAsync))
                 .Wrap(std::move(auth_block).err_status()),
             nullptr, std::nullopt);
    return;
  }
  ReportDeriveAuthBlock(auth_block_type);

  // This lambda functions to keep the auth_block reference valid until
  // the results are returned through derive_callback.
  AuthBlock* auth_block_ptr = auth_block->get();
  auto managed_callback = base::BindOnce(
      [](std::unique_ptr<AuthBlock> owned_auth_block,
         AuthBlock::DeriveCallback callback, CryptohomeStatus error,
         std::unique_ptr<KeyBlobs> key_blobs,
         std::optional<AuthBlock::SuggestedAction> suggested_action) {
        std::move(callback).Run(std::move(error), std::move(key_blobs),
                                suggested_action);
      },
      std::move(auth_block.value()), std::move(derive_callback));

  auth_block_ptr->Derive(auth_input, auth_state, std::move(managed_callback));
}

void AuthBlockUtilityImpl::SelectAuthFactorWithAuthBlock(
    AuthBlockType auth_block_type,
    const AuthInput& auth_input,
    std::vector<AuthFactor> auth_factors,
    AuthBlock::SelectFactorCallback select_callback) {
  CryptoStatusOr<std::unique_ptr<AuthBlock>> auth_block =
      GetAuthBlockWithType(auth_block_type, auth_input);
  if (!auth_block.ok()) {
    LOG(ERROR) << "Failed to retrieve auth block.";
    std::move(select_callback)
        .Run(MakeStatus<CryptohomeCryptoError>(
                 CRYPTOHOME_ERR_LOC(
                     kLocAuthBlockUtilNoAuthBlockInSelectAuthFactor))
                 .Wrap(std::move(auth_block).err_status()),
             std::nullopt, std::nullopt);
    return;
  }
  ReportSelectFactorAuthBlock(auth_block_type);

  // This lambda functions to keep the auth_block reference valid until
  // the results are returned through select_callback.
  AuthBlock* auth_block_ptr = auth_block->get();
  auto managed_callback = base::BindOnce(
      [](std::unique_ptr<AuthBlock> owned_auth_block,
         AuthBlock::SelectFactorCallback callback, CryptohomeStatus error,
         std::optional<AuthInput> auth_input,
         std::optional<AuthFactor> auth_factor) {
        std::move(callback).Run(std::move(error), std::move(auth_input),
                                std::move(auth_factor));
      },
      std::move(auth_block.value()), std::move(select_callback));

  auth_block_ptr->SelectFactor(auth_input, std::move(auth_factors),
                               std::move(managed_callback));
}

CryptoStatusOr<AuthBlockType>
AuthBlockUtilityImpl::SelectAuthBlockTypeForCreation(
    base::span<const AuthBlockType> block_types) const {
  // Default status if there are no entries in the returned priority list.
  CryptoStatus status = MakeStatus<CryptohomeCryptoError>(
      CRYPTOHOME_ERR_LOC(kLocAuthBlockUtilEmptyListInGetAuthBlockWithType),
      ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
      CryptoError::CE_OTHER_CRYPTO);
  for (AuthBlockType candidate_type : block_types) {
    status = IsAuthBlockSupported(candidate_type);
    if (status.ok()) {
      return candidate_type;
    }
  }
  // No suitable block was found. As we need to return only one error, take it
  // from the last attempted candidate (it's likely the most permissive one), if
  // any.
  return MakeStatus<CryptohomeCryptoError>(
             CRYPTOHOME_ERR_LOC(
                 kLocAuthBlockUtilNoSupportedInGetAuthBlockWithType),
             ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}))
      .Wrap(std::move(status));
}

CryptoStatus AuthBlockUtilityImpl::IsAuthBlockSupported(
    AuthBlockType auth_block_type) const {
  GenericAuthBlockFunctions generic(
      platform_, features_, challenge_credentials_helper_,
      key_challenge_service_factory_, bio_service_, crypto_);
  return generic.IsSupported(auth_block_type);
}

CryptoStatusOr<std::unique_ptr<AuthBlock>>
AuthBlockUtilityImpl::GetAuthBlockWithType(AuthBlockType auth_block_type,
                                           const AuthInput& auth_input) {
  if (auto status = IsAuthBlockSupported(auth_block_type); !status.ok()) {
    return MakeStatus<CryptohomeCryptoError>(
               CRYPTOHOME_ERR_LOC(
                   kLocAuthBlockUtilNotSupportedInGetAuthBlockWithType))
        .Wrap(std::move(status));
  }
  GenericAuthBlockFunctions generic(
      platform_, features_, challenge_credentials_helper_,
      key_challenge_service_factory_, bio_service_, crypto_);
  auto auth_block = generic.GetAuthBlockWithType(auth_block_type, auth_input);
  if (!auth_block) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(
            kLocAuthBlockUtilUnknownUnsupportedInGetAuthBlockWithType),
        ErrorActionSet(
            {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kAuth}),
        CryptoError::CE_OTHER_CRYPTO);
  }
  return auth_block;
}

std::optional<AuthBlockType> AuthBlockUtilityImpl::GetAuthBlockTypeFromState(
    const AuthBlockState& auth_block_state) const {
  GenericAuthBlockFunctions generic(
      platform_, features_, challenge_credentials_helper_,
      key_challenge_service_factory_, bio_service_, crypto_);
  return generic.GetAuthBlockTypeFromState(auth_block_state);
}

void AuthBlockUtilityImpl::PrepareAuthBlockForRemoval(
    const AuthBlockState& auth_block_state, CryptohomeStatusCallback callback) {
  std::optional<AuthBlockType> auth_block_type =
      GetAuthBlockTypeFromState(auth_block_state);
  if (!auth_block_type) {
    LOG(ERROR) << "Unsupported auth factor type.";
    std::move(callback).Run(MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(
            kLocAuthBlockUtilUnsupportedInPrepareAuthBlockForRemoval),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO));
    return;
  }

  // Should not create ChallengeCredential AuthBlock, no underlying
  // removal of the AuthBlock needed. Because of this, auth_input
  // can be an empty input.
  if (auth_block_type == AuthBlockType::kChallengeCredential) {
    std::move(callback).Run(OkStatus<CryptohomeError>());
    return;
  }

  AuthInput auth_input;
  CryptoStatusOr<std::unique_ptr<AuthBlock>> auth_block =
      GetAuthBlockWithType(*auth_block_type, auth_input);
  if (!auth_block.ok()) {
    LOG(ERROR) << "Failed to retrieve auth block.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocAuthBlockUtilNoAuthBlockInPrepareForRemoval))
            .Wrap(std::move(auth_block).err_status()));
    return;
  }

  auth_block.value()->PrepareForRemoval(auth_block_state, std::move(callback));
}

CryptoStatus AuthBlockUtilityImpl::GenerateRecoveryRequest(
    const ObfuscatedUsername& obfuscated_username,
    const cryptorecovery::RequestMetadata& request_metadata,
    const brillo::Blob& epoch_response,
    const CryptohomeRecoveryAuthBlockState& state,
    const hwsec::RecoveryCryptoFrontend* recovery_hwsec,
    brillo::SecureBlob* out_recovery_request,
    brillo::SecureBlob* out_ephemeral_pub_key) const {
  // Check if the required fields are set on CryptohomeRecoveryAuthBlockState.
  if (state.hsm_payload.empty() || state.channel_pub_key.empty() ||
      state.encrypted_channel_priv_key.empty()) {
    LOG(ERROR) << "CryptohomeRecoveryAuthBlockState is invalid";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocAuthBlockStateInvalidInGenerateRecoveryRequest),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  // Deserialize HSM payload from CryptohomeRecoveryAuthBlockState.
  cryptorecovery::HsmPayload hsm_payload;
  if (!cryptorecovery::DeserializeHsmPayloadFromCbor(state.hsm_payload,
                                                     &hsm_payload)) {
    LOG(ERROR) << "Failed to deserialize HSM payload";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(
            kLocFailedDeserializeHsmPayloadInGenerateRecoveryRequest),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  // Parse epoch response, which is sent from Chrome, to proto.
  cryptorecovery::CryptoRecoveryEpochResponse epoch_response_proto;
  if (!epoch_response_proto.ParseFromString(
          brillo::BlobToString(epoch_response))) {
    LOG(ERROR) << "Failed to parse epoch response";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(
            kLocFailedParseEpochResponseInGenerateRecoveryRequest),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  if (!recovery_hwsec) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(
            kLocFailedToGetRecoveryCryptoBackendInGenerateRecoveryRequest),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  std::unique_ptr<cryptorecovery::RecoveryCryptoImpl> recovery =
      cryptorecovery::RecoveryCryptoImpl::Create(recovery_hwsec, platform_);

  // Generate recovery request proto which will be sent back to Chrome, and then
  // to the recovery server.
  cryptorecovery::GenerateRecoveryRequestRequest
      generate_recovery_request_input_param(
          {.hsm_payload = hsm_payload,
           .request_meta_data = request_metadata,
           .epoch_response = epoch_response_proto,
           .encrypted_rsa_priv_key = state.encrypted_rsa_priv_key,
           .encrypted_channel_priv_key = state.encrypted_channel_priv_key,
           .channel_pub_key = state.channel_pub_key,
           .obfuscated_username = obfuscated_username});
  cryptorecovery::CryptoRecoveryRpcRequest recovery_request;
  if (!recovery->GenerateRecoveryRequest(generate_recovery_request_input_param,
                                         &recovery_request,
                                         out_ephemeral_pub_key)) {
    LOG(ERROR) << "Call to GenerateRecoveryRequest failed";
    // TODO(b/231297066): send more specific error.
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocFailedGenerateRecoveryRequest),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  // Serialize recovery request proto.
  *out_recovery_request =
      brillo::SecureBlob(recovery_request.SerializeAsString());
  return OkStatus<CryptohomeCryptoError>();
}

}  // namespace cryptohome
