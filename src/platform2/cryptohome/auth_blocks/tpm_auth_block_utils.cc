// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/tpm_auth_block_utils.h"

#include <string>
#include <utility>

#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <libhwsec/status.h>

#include "cryptohome/crypto_error.h"
#include "cryptohome/cryptohome_key_loader.h"
#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/error/cryptohome_tpm_error.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/vault_keyset.pb.h"

using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::CryptohomeTPMError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec::TPMErrorBase;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
using hwsec_foundation::status::StatusChain;

namespace cryptohome {

TpmAuthBlockUtils::TpmAuthBlockUtils(const hwsec::CryptohomeFrontend* hwsec,
                                     CryptohomeKeyLoader* cryptohome_key_loader)
    : hwsec_(hwsec), cryptohome_key_loader_(cryptohome_key_loader) {}

CryptoError TpmAuthBlockUtils::TPMRetryActionToCrypto(
    const hwsec::TPMRetryAction action) {
  switch (action) {
    case hwsec::TPMRetryAction::kCommunication:
    case hwsec::TPMRetryAction::kLater:
      return CryptoError::CE_TPM_COMM_ERROR;
    case hwsec::TPMRetryAction::kDefend:
      return CryptoError::CE_TPM_DEFEND_LOCK;
    case hwsec::TPMRetryAction::kReboot:
      return CryptoError::CE_TPM_REBOOT;
    default:
      // TODO(chromium:709646): kNoRetry maps here now. Find
      // a better corresponding CryptoError.
      return CryptoError::CE_TPM_CRYPTO;
  }
}

[[clang::return_typestate(unconsumed)]]  //
CryptoStatus
TpmAuthBlockUtils::TPMErrorToCryptohomeCryptoError(
    hwsec::Status err                       //
    [[clang::param_typestate(unconsumed)]]  //
    [[clang::return_typestate(consumed)]]) {
  return MakeStatus<CryptohomeTPMError>(std::move(err));
}

CryptoStatus TpmAuthBlockUtils::IsTPMPubkeyHash(
    const brillo::SecureBlob& hash) const {
  hwsec::StatusOr<brillo::Blob> pub_key_hash =
      hwsec_->GetPubkeyHash(cryptohome_key_loader_->GetCryptohomeKey());
  if (!pub_key_hash.ok()) {
    LOG(ERROR) << "Unable to get the cryptohome public key from the TPM: "
               << pub_key_hash.status();
    ReportCryptohomeError(kCannotReadTpmPublicKey);
    return MakeStatus<CryptohomeCryptoError>(
               CRYPTOHOME_ERR_LOC(
                   kLocTpmAuthBlockUtilsGetPubkeyFailedInPubkeyHash),
               ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                               PossibleAction::kReboot,
                               PossibleAction::kPowerwash}))
        .Wrap(TPMErrorToCryptohomeCryptoError(
            std::move(pub_key_hash).err_status()));
  }

  if ((hash.size() != pub_key_hash->size()) ||
      (brillo::SecureMemcmp(hash.data(), pub_key_hash->data(),
                            pub_key_hash->size()))) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocTpmAuthBlockUtilsHashIncorrectInPubkeyHash),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                        PossibleAction::kReboot, PossibleAction::kPowerwash}),
        CryptoError::CE_TPM_FATAL);
  }
  return OkStatus<CryptohomeCryptoError>();
}

CryptoStatus TpmAuthBlockUtils::CheckTPMReadiness(
    bool has_tpm_key,
    bool has_tpm_public_key_hash,
    const brillo::SecureBlob& tpm_public_key_hash) {
  if (!has_tpm_key) {
    LOG(ERROR) << "Decrypting with TPM, but no TPM key present.";
    ReportCryptohomeError(kDecryptAttemptButTpmKeyMissing);
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocTpmAuthBlockUtilsNoTpmKeyInCheckReadiness),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                        PossibleAction::kReboot, PossibleAction::kPowerwash}),
        CryptoError::CE_TPM_FATAL);
  }

  // If the TPM is enabled but not owned, and the keyset is TPM wrapped, then
  // it means the TPM has been cleared since the last login, and is not
  // re-owned.  In this case, the SRK is cleared and we cannot recover the
  // keyset.
  hwsec::StatusOr<bool> is_enabled = hwsec_->IsEnabled();
  hwsec::StatusOr<bool> is_ready = hwsec_->IsReady();
  bool enabled = is_enabled.ok() && *is_enabled;
  bool ready = is_ready.ok() && *is_ready;
  if (enabled && !ready) {
    LOG(ERROR) << "Fatal error--the TPM is enabled but not owned, and this "
               << "keyset was wrapped by the TPM.  It is impossible to "
               << "recover this keyset.";
    ReportCryptohomeError(kDecryptAttemptButTpmNotOwned);
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocTpmAuthBlockUtilsTpmNotOwnedInCheckReadiness),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                        PossibleAction::kReboot, PossibleAction::kPowerwash}),
        CryptoError::CE_TPM_FATAL);
  }

  if (!cryptohome_key_loader_->HasCryptohomeKey()) {
    LOG(ERROR) << "Vault keyset is wrapped by the TPM, but the TPM is "
               << "unavailable.";
    ReportCryptohomeError(kDecryptAttemptButTpmNotAvailable);
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(
            kLocTpmAuthBlockUtilsNoCryptohomeKeyInCheckReadiness),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                        PossibleAction::kReboot, PossibleAction::kPowerwash}),
        CryptoError::CE_TPM_REBOOT);
  }

  // This is a validity check that the keys still match.
  if (has_tpm_public_key_hash) {
    CryptoStatus error = IsTPMPubkeyHash(tpm_public_key_hash);
    if (!error.ok()) {
      LOG(ERROR) << "TPM public key hash mismatch.";
      ReportCryptohomeError(kDecryptAttemptButTpmKeyMismatch);
      return MakeStatus<CryptohomeCryptoError>(
                 CRYPTOHOME_ERR_LOC(
                     kLocTpmAuthBlockUtilsCHKeyMismatchInCheckReadiness),
                 ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                                 PossibleAction::kReboot,
                                 PossibleAction::kPowerwash}))
          .Wrap(std::move(error));
    }
  }

  return OkStatus<CryptohomeCryptoError>();
}

}  // namespace cryptohome
