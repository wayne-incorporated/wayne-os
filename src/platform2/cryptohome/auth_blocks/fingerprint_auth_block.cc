// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/fingerprint_auth_block.h"

#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <base/notreached.h>
#include <base/time/time.h>
#include <libhwsec/frontend/cryptohome/frontend.h>
#include <libhwsec/status.h>
#include <libhwsec-foundation/crypto/hmac.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>

#include "cryptohome/auth_blocks/auth_block.h"
#include "cryptohome/auth_blocks/tpm_auth_block_utils.h"
#include "cryptohome/crypto.h"
#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/error/cryptohome_le_cred_error.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/error/locations.h"
#include "cryptohome/error/utilities.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/le_credential_manager.h"

namespace cryptohome {

namespace {
using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::CryptohomeError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec_foundation::CreateSecureRandomBlob;
using hwsec_foundation::HmacSha256;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;

// String used as vector in HMAC operation to derive fek_key from auth stack and
// GSC secrets.
constexpr char kFekKeyHmacData[] = "fek_key";

constexpr uint8_t kFingerprintAuthChannel = 0;
constexpr uint32_t kInfiniteDelay = std::numeric_limits<uint32_t>::max();
constexpr size_t kHeSecretSize = 32;
constexpr size_t kResetSecretSize = 32;

constexpr struct {
  uint32_t attempts;
  uint32_t delay;
} kDefaultDelaySchedule[] = {
    {5, kInfiniteDelay},
};
constexpr base::TimeDelta kExpirationLockout = base::Days(14);

std::vector<hwsec::OperationPolicySetting> GetValidPoliciesOfUser(
    const ObfuscatedUsername& obfuscated_username) {
  return std::vector<hwsec::OperationPolicySetting>{
      hwsec::OperationPolicySetting{
          .device_config_settings =
              hwsec::DeviceConfigSettings{
                  .current_user =
                      hwsec::DeviceConfigSettings::CurrentUserSetting{
                          .username = std::nullopt,
                      },
              },
      },
      hwsec::OperationPolicySetting{
          .device_config_settings =
              hwsec::DeviceConfigSettings{
                  .current_user =
                      hwsec::DeviceConfigSettings::CurrentUserSetting{
                          .username = *obfuscated_username,
                      },
              },
      },
  };
}

}  // namespace

FingerprintAuthBlock::FingerprintAuthBlock(LECredentialManager* le_manager,
                                           BiometricsAuthBlockService* service)
    : AuthBlock(kBiometrics), le_manager_(le_manager), service_(service) {
  CHECK(le_manager_);
  CHECK(service_);
}

CryptoStatus FingerprintAuthBlock::IsSupported(
    Crypto& crypto, AsyncInitPtr<BiometricsAuthBlockService> bio_service) {
  if (!bio_service) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocFingerprintAuthBlockNoServiceInIsSupported),
        ErrorActionSet({PossibleAction::kAuth}), CryptoError::CE_OTHER_CRYPTO);
  }
  if (!bio_service->IsReady()) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocFingerprintAuthBlockServiceNotReadyIsSupported),
        ErrorActionSet({PossibleAction::kAuth}), CryptoError::CE_OTHER_CRYPTO);
  }

  const hwsec::CryptohomeFrontend* frontend = crypto.GetHwsec();
  DCHECK(frontend);
  hwsec::StatusOr<bool> is_ready = frontend->IsReady();
  if (!is_ready.ok()) {
    return MakeStatus<CryptohomeCryptoError>(
               CRYPTOHOME_ERR_LOC(
                   kLocFingerprintAuthBlockHwsecReadyErrorInIsSupported),
               ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}))
        .Wrap(TpmAuthBlockUtils::TPMErrorToCryptohomeCryptoError(
            std::move(is_ready).err_status()));
  }
  if (!is_ready.value()) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocFingerprintAuthBlockHwsecNotReadyInIsSupported),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  hwsec::StatusOr<bool> enabled =
      crypto.GetHwsec()->IsBiometricsPinWeaverEnabled();
  if (!enabled.ok()) {
    return MakeStatus<CryptohomeCryptoError>(
               CRYPTOHOME_ERR_LOC(
                   kLocFingerprintAuthBlockPinWeaverCheckFailInIsSupported))
        .Wrap(TpmAuthBlockUtils::TPMErrorToCryptohomeCryptoError(
            std::move(enabled).err_status()));
  }
  if (!enabled.value()) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(
            kLocFingerprintAuthBlockPinWeaverNotEnabledInIsSupported),
        ErrorActionSet({PossibleAction::kAuth}), CryptoError::CE_OTHER_CRYPTO);
  }

  if (!crypto.le_manager()) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocFingerprintAuthBlockNullLeManagerInIsSupported),
        ErrorActionSet(
            {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kAuth}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  return OkStatus<CryptohomeCryptoError>();
}

std::unique_ptr<AuthBlock> FingerprintAuthBlock::New(
    Crypto& crypto, AsyncInitPtr<BiometricsAuthBlockService> bio_service) {
  auto* le_manager = crypto.le_manager();
  if (le_manager && bio_service) {
    return std::make_unique<FingerprintAuthBlock>(le_manager,
                                                  bio_service.get());
  }
  return nullptr;
}

void FingerprintAuthBlock::Create(const AuthInput& auth_input,
                                  CreateCallback callback) {
  if (!auth_input.obfuscated_username.has_value()) {
    LOG(ERROR) << "Missing obfuscated_username.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocFingerprintAuthBlockNoUsernameInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, nullptr);
    return;
  }
  std::optional<uint64_t> rate_limiter_label = std::nullopt,
                          created_rate_limiter_label = std::nullopt;
  // reset_secret here represents the existing/created rate limiter leaf's reset
  // secret. The same value will be used as the reset secret for the actual
  // fingerprint credential leaf. It usually never needs to be reset as
  // its authentication shouldn't never fail, but we still need to be able to
  // reset it when it's locked.
  std::optional<brillo::SecureBlob> reset_secret;
  if (auth_input.rate_limiter_label.has_value()) {
    rate_limiter_label = *auth_input.rate_limiter_label;
    reset_secret = auth_input.reset_secret;
  } else {
    reset_secret = CreateSecureRandomBlob(kResetSecretSize);
    CryptoStatusOr<uint64_t> label =
        CreateRateLimiter(*auth_input.obfuscated_username, *reset_secret);
    if (!label.ok()) {
      std::move(callback).Run(
          MakeStatus<CryptohomeCryptoError>(
              CRYPTOHOME_ERR_LOC(
                  kLocFingerprintAuthBlockCreateRateLimiterFailedInCreate),
              ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}))
              .Wrap(std::move(label).err_status()),
          nullptr, nullptr);
      return;
    }
    created_rate_limiter_label = rate_limiter_label = *label;
  }
  if (!rate_limiter_label.has_value() || !reset_secret.has_value()) {
    LOG(ERROR) << "Missing label or reset_secret.";
    std::move(callback).Run(
        MakeStatus<CryptohomeError>(
            CRYPTOHOME_ERR_LOC(kLocFingerprintAuthBlockNoResetSecretInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT),
        nullptr, nullptr);
    return;
  }

  std::optional<brillo::Blob> nonce = service_->TakeNonce();
  if (!nonce.has_value()) {
    LOG(ERROR) << "Missing nonce, probably meaning there isn't a completed "
                  "enroll session.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocFingerprintAuthBlockNoNonceInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, nullptr);
    return;
  }
  LECredStatusOr<LECredentialManager::StartBiometricsAuthReply> reply =
      le_manager_->StartBiometricsAuth(kFingerprintAuthChannel,
                                       *rate_limiter_label, *nonce);
  if (!reply.ok()) {
    LOG(ERROR) << "Failed to start biometrics auth with PinWeaver.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocFingerprintAuthBlockStartBioAuthFailedInCreate))
            .Wrap(std::move(reply).err_status()),
        nullptr, nullptr);
    return;
  }
  LECredStatus reset_status = le_manager_->ResetCredential(
      *rate_limiter_label, *reset_secret, /*strong_reset=*/false);
  if (!reset_status.ok()) {
    // TODO(b/275027852): Report metrics because we silently fail here.
    LOG(WARNING)
        << "Failed to reset rate-limiter during KeyBlobs creation. This "
           "doesn't block the creation but shouldn't normally happen.";
  }
  BiometricsAuthBlockService::OperationInput input{
      .nonce = std::move(reply->server_nonce),
      .encrypted_label_seed = std::move(reply->encrypted_he_secret),
      .iv = std::move(reply->iv),
  };
  service_->CreateCredential(
      input, base::BindOnce(&FingerprintAuthBlock::ContinueCreate,
                            weak_factory_.GetWeakPtr(), std::move(callback),
                            *auth_input.obfuscated_username, *reset_secret,
                            created_rate_limiter_label));
}

void FingerprintAuthBlock::Derive(const AuthInput& auth_input,
                                  const AuthBlockState& state,
                                  DeriveCallback callback) {
  if (!auth_input.fingerprint_auth_input.has_value() ||
      !auth_input.fingerprint_auth_input->auth_secret.has_value()) {
    LOG(ERROR) << "Missing auth_secret.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocFingerprintAuthBlockNoAuthSecretInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }
  if (!auth_input.user_input.has_value()) {
    LOG(ERROR) << "Missing auth_pin.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocFingerprintAuthBlockNoAuthPinInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }

  const FingerprintAuthBlockState* auth_state;
  if (!(auth_state = std::get_if<FingerprintAuthBlockState>(&state.state))) {
    LOG(ERROR) << "No FingerprintAuthBlockState in AuthBlockState.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocFingerprintAuthBlockWrongAuthBlockStateInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }
  if (!auth_state->gsc_secret_label.has_value()) {
    LOG(ERROR)
        << "Invalid FingerprintAuthBlockState: missing gsc_secret_label.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocFingerprintAuthBlockNoGscSecretLabelInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }

  brillo::SecureBlob gsc_secret, unused_reset_secret;
  LECredStatus status = le_manager_->CheckCredential(
      *auth_state->gsc_secret_label, *auth_input.user_input, &gsc_secret,
      &unused_reset_secret);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to check biometrics secret with PinWeaver.";
    // Include kDevCheckUnexpectedState as according to the protocol this
    // authentication should never fail.
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocFingerprintAuthBlockCheckCredentialFailedInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}))
            .Wrap(std::move(status).err_status()),
        nullptr, std::nullopt);
    return;
  }

  auto key_blobs = std::make_unique<KeyBlobs>();
  auto hmac_key = brillo::SecureBlob::Combine(
      gsc_secret, *auth_input.fingerprint_auth_input->auth_secret);
  key_blobs->vkk_key =
      HmacSha256(hmac_key, brillo::BlobFromString(kFekKeyHmacData));
  std::move(callback).Run(OkStatus<CryptohomeError>(), std::move(key_blobs),
                          std::nullopt);
}

// SelectFactor for FingerprintAuthBlock is actually doing the heavy-lifting
// job for Derive, if you compare it with Create. This is because we only know
// the actual AuthFactor the user used (the correct finger) after biometrics
// auth stack returns a positive match verdict.
void FingerprintAuthBlock::SelectFactor(const AuthInput& auth_input,
                                        std::vector<AuthFactor> auth_factors,
                                        SelectFactorCallback callback) {
  if (!auth_input.rate_limiter_label.has_value()) {
    LOG(ERROR) << "Missing rate_limiter_label.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocFingerprintAuthBlockNoUsernameInSelect),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        std::nullopt, std::nullopt);
    return;
  }

  std::optional<brillo::Blob> nonce = service_->TakeNonce();
  if (!nonce.has_value()) {
    LOG(ERROR) << "Missing nonce, probably meaning there isn't a completed "
                  "authenticate session.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocFingerprintAuthBlockNoNonceInSelect),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        std::nullopt, std::nullopt);
    return;
  }
  LECredStatusOr<LECredentialManager::StartBiometricsAuthReply> reply =
      le_manager_->StartBiometricsAuth(kFingerprintAuthChannel,
                                       *auth_input.rate_limiter_label, *nonce);
  if (!reply.ok()) {
    LOG(ERROR) << "Failed to start biometrics auth with PinWeaver.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocFingerprintAuthBlockStartBioAuthFailedInSelect))
            .Wrap(std::move(reply).err_status()),
        std::nullopt, std::nullopt);
    return;
  }
  BiometricsAuthBlockService::OperationInput input{
      .nonce = std::move(reply->server_nonce),
      .encrypted_label_seed = std::move(reply->encrypted_he_secret),
      .iv = std::move(reply->iv),
  };
  service_->MatchCredential(
      input,
      base::BindOnce(&FingerprintAuthBlock::ContinueSelect,
                     weak_factory_.GetWeakPtr(), std::move(callback),
                     std::move(auth_factors), *auth_input.rate_limiter_label));
}

void FingerprintAuthBlock::PrepareForRemoval(const AuthBlockState& state,
                                             StatusCallback callback) {
  auto* fp_state = std::get_if<FingerprintAuthBlockState>(&state.state);
  if (!fp_state) {
    LOG(ERROR) << "Failed to get AuthBlockState in fingerprint auth block.";
    // This error won't be solved by retrying, go ahead and delete the auth
    // factor anyway.
    std::move(callback).Run(OkStatus<CryptohomeCryptoError>());
    return;
  }

  // Ensure that the auth block state has template_id.
  if (fp_state->template_id.empty()) {
    // This error won't be solved by retrying, continue to delete the
    // credential leaf.
    LOG(ERROR) << "FingerprintAuthBlockState does not have template_id";
  } else {
    // TODO(b/277274350): Remove the encrypted fingerprint template.
    // If removal of the template fails, we need to return an error to fail the
    // whole Remove operation because biod's template state needs to be
    // consistent with cryptohome's.
  }

  // Ensure that the auth block state has gsc_secret_label.
  if (!fp_state->gsc_secret_label.has_value()) {
    LOG(ERROR) << "FingerprintAuthBlockState does not have gsc_secret_label";
    // This error won't be solved by retrying, go ahead and delete the auth
    // factor anyway.
    std::move(callback).Run(OkStatus<CryptohomeCryptoError>());
    return;
  }

  LECredStatus status =
      le_manager_->RemoveCredential(fp_state->gsc_secret_label.value());
  if (!status.ok()) {
    if (status->local_lecred_error() ==
        LECredError::LE_CRED_ERROR_INVALID_LABEL) {
      LOG(ERROR) << "Invalid gsc_secret_label in fingerprint auth block: "
                 << status;
      // This error won't be solved by retrying, go ahead and delete the auth
      // factor anyway.
      std::move(callback).Run(OkStatus<CryptohomeCryptoError>());
      return;
    }
    // Other LE errors might be resolved by retrying, so fail the remove
    // operation here.
    std::move(callback).Run(std::move(status));
    return;
  }

  // Rate limiter leaf is not removed since it is shared among all fingerprint
  // auth factors. Also, even if all fingerprint auth factors are removed,
  // we still keep the rate limiter leaf so in the future new fingerprint
  // auth factors can be added more efficiently.
  std::move(callback).Run(OkStatus<CryptohomeCryptoError>());
}

CryptoStatusOr<uint64_t> FingerprintAuthBlock::CreateRateLimiter(
    const ObfuscatedUsername& obfuscated_username,
    const brillo::SecureBlob& reset_secret) {
  std::vector<hwsec::OperationPolicySetting> policies =
      GetValidPoliciesOfUser(obfuscated_username);

  std::map<uint32_t, uint32_t> delay_sched;
  for (const auto& entry : kDefaultDelaySchedule) {
    delay_sched[entry.attempts] = entry.delay;
  }

  uint64_t label;
  LECredStatus ret = le_manager_->InsertRateLimiter(
      kFingerprintAuthChannel, policies, reset_secret, delay_sched,
      kExpirationLockout.InSeconds(), &label);
  if (!ret.ok()) {
    return ret;
  }
  return label;
}

void FingerprintAuthBlock::ContinueCreate(
    CreateCallback callback,
    const ObfuscatedUsername& obfuscated_username,
    const brillo::SecureBlob& reset_secret,
    std::optional<uint64_t> created_label,
    CryptohomeStatusOr<BiometricsAuthBlockService::OperationOutput> output) {
  if (!output.ok()) {
    LOG(ERROR) << "Failed to create biometrics credential.";
    std::move(callback).Run(
        MakeStatus<CryptohomeError>(
            CRYPTOHOME_ERR_LOC(
                kLocFingerprintAuthBlockCreateCredentialFailedInCreate))
            .Wrap(std::move(output).err_status()),
        nullptr, nullptr);
    return;
  }

  std::vector<hwsec::OperationPolicySetting> policies =
      GetValidPoliciesOfUser(obfuscated_username);

  const auto he_secret = CreateSecureRandomBlob(kHeSecretSize);

  // Use the strictest delay schedule. This is because the rate-limit of a
  // fingerprint credential is guarded by the rate-limiter and not the
  // credential leaf itself. So when properly following the protocol, the
  // credential authentication should never fail.
  std::map<uint32_t, uint32_t> delay_sched{{1, kInfiniteDelay}};

  uint64_t label;
  LECredStatus ret = le_manager_->InsertCredential(
      policies, /*le_secret=*/output->auth_pin,
      /*he_secret=*/he_secret, reset_secret, delay_sched,
      /*expiration_delay=*/std::nullopt, &label);
  if (!ret.ok()) {
    LOG(ERROR) << "Failed to insert the fingerprint PinWeaver credential.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocFingerprintAuthBlockInsertCredentialFailedInCreate))
            .Wrap(std::move(ret)),
        nullptr, nullptr);
    return;
  }
  // There should be no failing branches below this.
  // Put every step that might fail before creating the PinWeaver leaf, to
  // avoid creating unused leaves whenever possible.

  auto auth_state = std::make_unique<AuthBlockState>();
  FingerprintAuthBlockState fingerprint_auth_state;
  fingerprint_auth_state.template_id = std::move(output->record_id);
  fingerprint_auth_state.gsc_secret_label = label;
  auth_state->state = std::move(fingerprint_auth_state);

  auto key_blobs = std::make_unique<KeyBlobs>();
  auto hmac_key = brillo::SecureBlob::Combine(he_secret, output->auth_secret);
  key_blobs->vkk_key =
      HmacSha256(hmac_key, brillo::BlobFromString(kFekKeyHmacData));
  key_blobs->reset_secret = reset_secret;
  key_blobs->rate_limiter_label = created_label;

  std::move(callback).Run(OkStatus<CryptohomeCryptoError>(),
                          std::move(key_blobs), std::move(auth_state));
}

void FingerprintAuthBlock::ContinueSelect(
    SelectFactorCallback callback,
    std::vector<AuthFactor> auth_factors,
    uint64_t rate_limiter_label,
    CryptohomeStatusOr<BiometricsAuthBlockService::OperationOutput> output) {
  if (!output.ok()) {
    LOG(ERROR) << "Failed to authenticate biometrics credential.";
    if (IsLocked(rate_limiter_label)) {
      std::move(callback).Run(
          MakeStatus<CryptohomeError>(
              CRYPTOHOME_ERR_LOC(
                  kLocFingerprintAuthBlockAuthenticateCredentialLockedInSelect),
              ErrorActionSet(PrimaryAction::kLeLockedOut),
              user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_DENIED)
              .Wrap(std::move(output).err_status()),
          std::nullopt, std::nullopt);
      return;
    }
    std::move(callback).Run(
        MakeStatus<CryptohomeError>(
            CRYPTOHOME_ERR_LOC(
                kLocFingerprintAuthBlockAuthenticateCredentialFailedInSelect))
            .Wrap(std::move(output).err_status()),
        std::nullopt, std::nullopt);
    return;
  }

  // For consistency with PIN AuthFactor, we put the AuthPin in the user_input
  // field.
  AuthInput auth_input{
      .user_input = std::move(output->auth_pin),
      .fingerprint_auth_input =
          FingerprintAuthInput{.auth_secret = std::move(output->auth_secret)},
  };

  // The MatchCredential reply contains the matched credential's record ID. We
  // can use that to match against the AuthBlockState of the candidate
  // auth factors.
  for (AuthFactor& auth_factor : auth_factors) {
    const FingerprintAuthBlockState* auth_state;
    if (!(auth_state = std::get_if<FingerprintAuthBlockState>(
              &auth_factor.auth_block_state().state))) {
      LOG(WARNING) << "Invalid AuthBlockState in candidates.";
      // We don't really need to return an error here, as the goal is to search
      // for the correct auth factor in the list.
      continue;
    }
    if (auth_state->template_id == output->record_id) {
      std::move(callback).Run(OkStatus<CryptohomeError>(),
                              std::move(auth_input), std::move(auth_factor));
      return;
    }
  }
  LOG(ERROR) << "Matching AuthFactor not found in candidates.";
  std::move(callback).Run(
      MakeStatus<CryptohomeError>(
          CRYPTOHOME_ERR_LOC(kLocFingerprintAuthBlockFactorNotFoundInSelect),
          ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
          user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_KEY_NOT_FOUND),
      std::nullopt, std::nullopt);
}

bool FingerprintAuthBlock::IsLocked(uint64_t label) {
  LECredStatusOr<uint32_t> delay = le_manager_->GetDelayInSeconds(label);
  if (!delay.ok()) {
    LOG(ERROR)
        << "Failed to obtain the delay in seconds in fingerprint auth block: "
        << std::move(delay).status();
    return false;
  }

  if (delay.value() > 0) {
    return true;
  }

  return false;
}

}  // namespace cryptohome
