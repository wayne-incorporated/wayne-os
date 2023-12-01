// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/challenge_credentials/challenge_credentials_generate_new_operation.h"

#include <optional>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <libhwsec/frontend/cryptohome/frontend.h>
#include <libhwsec/status.h>

#include "cryptohome/challenge_credentials/challenge_credentials_constants.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/username.h"

using brillo::Blob;
using brillo::CombineBlobs;
using brillo::SecureBlob;
using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::CryptohomeTPMError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
using hwsec_foundation::status::StatusChain;

namespace cryptohome {

namespace {

// Size, in bytes, of the secret value that will be sealed by HWSec signature
// sealing.
constexpr int kSecretSizeBytes = 32;

// Returns the signature algorithm that should be used for signing salt from the
// set of algorithms supported by the given key. Returns nullopt when no
// suitable algorithm was found.
std::optional<structure::ChallengeSignatureAlgorithm>
ChooseSaltSignatureAlgorithm(
    const structure::ChallengePublicKeyInfo& public_key_info) {
  DCHECK(public_key_info.signature_algorithm.size());
  std::optional<structure::ChallengeSignatureAlgorithm>
      currently_chosen_algorithm;
  // Respect the input's algorithm prioritization, with the exception of
  // considering SHA-1 as the least preferred option.
  for (auto algo : public_key_info.signature_algorithm) {
    currently_chosen_algorithm = algo;
    if (*currently_chosen_algorithm !=
        structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha1)
      break;
  }
  return currently_chosen_algorithm;
}

using HwsecAlgorithm = hwsec::CryptohomeFrontend::SignatureSealingAlgorithm;

HwsecAlgorithm ConvertAlgorithm(
    structure::ChallengeSignatureAlgorithm algorithm) {
  switch (algorithm) {
    case structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha1:
      return HwsecAlgorithm::kRsassaPkcs1V15Sha1;
    case structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha256:
      return HwsecAlgorithm::kRsassaPkcs1V15Sha256;
    case structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha384:
      return HwsecAlgorithm::kRsassaPkcs1V15Sha384;
    case structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha512:
      return HwsecAlgorithm::kRsassaPkcs1V15Sha512;
  }
  NOTREACHED();
  return static_cast<HwsecAlgorithm>(algorithm);
}

}  // namespace

ChallengeCredentialsGenerateNewOperation::
    ChallengeCredentialsGenerateNewOperation(
        KeyChallengeService* key_challenge_service,
        const hwsec::CryptohomeFrontend* hwsec,
        const Username& account_id,
        const structure::ChallengePublicKeyInfo& public_key_info,
        const ObfuscatedUsername& obfuscated_username,
        CompletionCallback completion_callback)
    : ChallengeCredentialsOperation(key_challenge_service),
      account_id_(account_id),
      public_key_info_(public_key_info),
      obfuscated_username_(obfuscated_username),
      completion_callback_(std::move(completion_callback)),
      hwsec_(hwsec) {}

ChallengeCredentialsGenerateNewOperation::
    ~ChallengeCredentialsGenerateNewOperation() = default;

void ChallengeCredentialsGenerateNewOperation::Start() {
  DCHECK(thread_checker_.CalledOnValidThread());
  CryptoStatus status = StartProcessing();
  if (!status.ok()) {
    LOG(ERROR) << "Failed to start the generation operation";
    Abort(std::move(status));
    // |this| can be already destroyed at this point.
  }
}

void ChallengeCredentialsGenerateNewOperation::Abort(
    CryptoStatus status [[clang::param_typestate(unconsumed)]]) {
  DCHECK(thread_checker_.CalledOnValidThread());
  CryptoStatus return_status = MakeStatus<CryptohomeCryptoError>(
                                   CRYPTOHOME_ERR_LOC(kLocChalCredNewAborted))
                                   .Wrap(std::move(status));

  // Invalidate weak pointers in order to cancel all jobs that are currently
  // waiting, to prevent them from running and consuming resources after our
  // abortion (in case |this| doesn't get destroyed immediately).
  //
  // Note that the already issued challenge requests don't get cancelled, so
  // their responses will be just ignored should they arrive later. The request
  // cancellation is not supported by the challenges IPC API currently, neither
  // it is supported by the API for smart card drivers in Chrome OS.
  weak_ptr_factory_.InvalidateWeakPtrs();
  CompleteWithError(&completion_callback_, std::move(return_status));
  // |this| can be already destroyed at this point.
}

CryptoStatus ChallengeCredentialsGenerateNewOperation::StartProcessing() {
  if (!hwsec_) {
    LOG(ERROR) << "Signature sealing is disabled";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocChalCredNewNoBackend),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }
  if (!public_key_info_.signature_algorithm.size()) {
    LOG(ERROR) << "The key does not support any signature algorithm";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocChalCredNewNoAlgorithm),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  CryptoStatus status = GenerateSalt();
  if (!status.ok()) {
    return status;
  }
  status = StartGeneratingSaltSignature();
  if (!status.ok()) {
    return status;
  }
  // TODO(crbug.com/842791): This is buggy: |this| may be already deleted by
  // that point, in case when the salt's challenge request failed synchronously.
  status = CreateTpmProtectedSecret();
  if (!status.ok()) {
    return status;
  }
  ProceedIfComputationsDone();
  return OkStatus<CryptohomeCryptoError>();
}

CryptoStatus ChallengeCredentialsGenerateNewOperation::GenerateSalt() {
  hwsec::StatusOr<Blob> salt_random_bytes =
      hwsec_->GetRandomBlob(kChallengeCredentialsSaltRandomByteCount);
  if (!salt_random_bytes.ok()) {
    LOG(ERROR) << "Failed to generate random bytes for the salt: "
               << salt_random_bytes.status();
    return MakeStatus<CryptohomeCryptoError>(
               CRYPTOHOME_ERR_LOC(kLocChalCredNewGenerateRandomSaltFailed),
               ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                               PossibleAction::kReboot}),
               CryptoError::CE_OTHER_CRYPTO)
        .Wrap(MakeStatus<CryptohomeTPMError>(
            std::move(salt_random_bytes).err_status()));
  }
  DCHECK_EQ(kChallengeCredentialsSaltRandomByteCount,
            salt_random_bytes->size());
  // IMPORTANT: Make sure the salt is prefixed with a constant. See the comment
  // on GetChallengeCredentialsSaltConstantPrefix() for details.
  salt_ = CombineBlobs(
      {GetChallengeCredentialsSaltConstantPrefix(), salt_random_bytes.value()});
  return OkStatus<CryptohomeCryptoError>();
}

CryptoStatus
ChallengeCredentialsGenerateNewOperation::StartGeneratingSaltSignature() {
  DCHECK(!salt_.empty());
  std::optional<structure::ChallengeSignatureAlgorithm>
      chosen_salt_signature_algorithm =
          ChooseSaltSignatureAlgorithm(public_key_info_);
  if (!chosen_salt_signature_algorithm) {
    LOG(ERROR) << "Failed to choose salt signature algorithm";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocChalCredNewCantChooseSaltSignatureAlgorithm),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }
  salt_signature_algorithm_ = *chosen_salt_signature_algorithm;
  MakeKeySignatureChallenge(
      account_id_, public_key_info_.public_key_spki_der, salt_,
      salt_signature_algorithm_,
      base::BindOnce(
          &ChallengeCredentialsGenerateNewOperation::OnSaltChallengeResponse,
          weak_ptr_factory_.GetWeakPtr()));
  return OkStatus<CryptohomeCryptoError>();
}

CryptoStatus
ChallengeCredentialsGenerateNewOperation::CreateTpmProtectedSecret() {
  hwsec::StatusOr<SecureBlob> tpm_protected_secret_value =
      hwsec_->GetRandomSecureBlob(kSecretSizeBytes);
  if (!tpm_protected_secret_value.ok()) {
    LOG(ERROR) << "Failed to generated random secure blob: "
               << tpm_protected_secret_value.status();
    TPMStatus status = MakeStatus<CryptohomeTPMError>(
        std::move(tpm_protected_secret_value).err_status());
    return MakeStatus<CryptohomeCryptoError>(
               CRYPTOHOME_ERR_LOC(kLocChalCredGenRandFailed))
        .Wrap(std::move(status));
  }

  std::vector<HwsecAlgorithm> key_sealing_algorithms;
  for (auto algo : public_key_info_.signature_algorithm) {
    key_sealing_algorithms.push_back(ConvertAlgorithm(algo));
  }

  hwsec::StatusOr<hwsec::SignatureSealedData> sealed_data =
      hwsec_->SealWithSignatureAndCurrentUser(
          *obfuscated_username_, tpm_protected_secret_value.value(),
          public_key_info_.public_key_spki_der, key_sealing_algorithms);
  if (!sealed_data.ok()) {
    LOG(ERROR) << "Failed to create hardware-protected secret: "
               << sealed_data.status();
    TPMStatus status =
        MakeStatus<CryptohomeTPMError>(std::move(sealed_data).err_status());
    return MakeStatus<CryptohomeCryptoError>(
               CRYPTOHOME_ERR_LOC(kLocChalCredNewSealFailed))
        .Wrap(std::move(status));
  }

  tpm_protected_secret_value_ = std::make_unique<SecureBlob>(
      std::move(tpm_protected_secret_value).value());
  tpm_sealed_secret_data_ = std::move(sealed_data).value();

  return OkStatus<CryptohomeCryptoError>();
}

void ChallengeCredentialsGenerateNewOperation::OnSaltChallengeResponse(
    CryptoStatusOr<std::unique_ptr<Blob>> salt_signature) {
  DCHECK(thread_checker_.CalledOnValidThread());
  if (!salt_signature.ok()) {
    LOG(ERROR) << "Salt signature challenge failed";
    Abort(std::move(salt_signature).err_status());
    // |this| can be already destroyed at this point.
    return;
  }
  salt_signature_ = std::move(salt_signature).value();
  ProceedIfComputationsDone();
}

void ChallengeCredentialsGenerateNewOperation::ProceedIfComputationsDone() {
  if (!salt_signature_ || !tpm_protected_secret_value_)
    return;

  auto signature_challenge_info =
      std::make_unique<structure::SignatureChallengeInfo>(
          ConstructKeysetSignatureChallengeInfo());

  auto passkey = std::make_unique<brillo::SecureBlob>(
      ConstructPasskey(*tpm_protected_secret_value_, *salt_signature_));
  Complete(&completion_callback_,
           ChallengeCredentialsHelper::GenerateNewOrDecryptResult(
               std::move(signature_challenge_info), std::move(passkey)));
  // |this| can be already destroyed at this point.
}

structure::SignatureChallengeInfo ChallengeCredentialsGenerateNewOperation::
    ConstructKeysetSignatureChallengeInfo() const {
  structure::SignatureChallengeInfo keyset_signature_challenge_info;
  keyset_signature_challenge_info.public_key_spki_der =
      public_key_info_.public_key_spki_der;
  keyset_signature_challenge_info.sealed_secret = tpm_sealed_secret_data_;
  keyset_signature_challenge_info.salt = salt_;
  keyset_signature_challenge_info.salt_signature_algorithm =
      salt_signature_algorithm_;
  return keyset_signature_challenge_info;
}

}  // namespace cryptohome
