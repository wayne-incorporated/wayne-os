// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/challenge_credentials/challenge_credentials_verify_key_operation.h"

#include <optional>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <crypto/scoped_openssl_types.h>
#include <libhwsec/frontend/cryptohome/frontend.h>
#include <libhwsec/status.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "cryptohome/error/location_utils.h"

using brillo::Blob;
using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::CryptohomeError;
using cryptohome::error::CryptohomeTPMError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec::TPMError;
using hwsec::TPMErrorBase;
using hwsec::TPMRetryAction;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
using hwsec_foundation::status::StatusChain;

namespace cryptohome {

namespace {

// Size of the verification challenge.
constexpr int kChallengeByteCount = 20;

// Returns the signature algorithm to be used for the verification.
std::optional<structure::ChallengeSignatureAlgorithm> ChooseChallengeAlgorithm(
    const structure::ChallengePublicKeyInfo& public_key_info) {
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

int GetOpenSslSignatureAlgorithmNid(
    structure::ChallengeSignatureAlgorithm algorithm) {
  switch (algorithm) {
    case structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha1:
      return NID_sha1;
    case structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha256:
      return NID_sha256;
    case structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha384:
      return NID_sha384;
    case structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha512:
      return NID_sha512;
  }
  return 0;
}

bool IsValidSignature(const Blob& public_key_spki_der,
                      structure::ChallengeSignatureAlgorithm algorithm,
                      const Blob& input,
                      const Blob& signature) {
  const int openssl_algorithm_nid = GetOpenSslSignatureAlgorithmNid(algorithm);
  if (!openssl_algorithm_nid) {
    LOG(ERROR)
        << "Unknown challenge algorithm for challenge signature verification";
    return false;
  }
  const EVP_MD* const openssl_digest =
      EVP_get_digestbynid(openssl_algorithm_nid);
  if (!openssl_digest) {
    LOG(ERROR) << "Error obtaining digest for challenge signature verification";
    return false;
  }
  const unsigned char* asn1_ptr = public_key_spki_der.data();
  crypto::ScopedEVP_PKEY openssl_public_key(
      d2i_PUBKEY(NULL, &asn1_ptr, public_key_spki_der.size()));
  if (!openssl_public_key) {
    LOG(ERROR)
        << "Error loading public key for challenge signature verification";
    return false;
  }
  crypto::ScopedEVP_MD_CTX openssl_context(EVP_MD_CTX_new());
  if (!openssl_context) {
    LOG(ERROR) << "Error creating challenge signature verification context";
    return false;
  }
  if (!EVP_DigestVerifyInit(openssl_context.get(),
                            /*EVP_PKEY_CTX **pctx=*/nullptr, openssl_digest,
                            /*ENGINE *e=*/nullptr, openssl_public_key.get())) {
    LOG(ERROR) << "Failed to initialize challenge signature verification";
    return false;
  }
  if (!EVP_DigestVerifyUpdate(openssl_context.get(), input.data(),
                              input.size())) {
    LOG(ERROR)
        << "Failed to update digest for challenge signature verification";
    return false;
  }
  if (EVP_DigestVerifyFinal(openssl_context.get(), signature.data(),
                            signature.size()) != 1) {
    LOG(ERROR) << "Challenge signature verification failed";
    return false;
  }
  return true;
}

}  // namespace

ChallengeCredentialsVerifyKeyOperation::ChallengeCredentialsVerifyKeyOperation(
    KeyChallengeService* key_challenge_service,
    const hwsec::CryptohomeFrontend* hwsec,
    const Username& account_id,
    const structure::ChallengePublicKeyInfo& public_key_info,
    CompletionCallback completion_callback)
    : ChallengeCredentialsOperation(key_challenge_service),
      hwsec_(hwsec),
      account_id_(account_id),
      public_key_info_(public_key_info),
      completion_callback_(std::move(completion_callback)) {}

ChallengeCredentialsVerifyKeyOperation::
    ~ChallengeCredentialsVerifyKeyOperation() = default;

void ChallengeCredentialsVerifyKeyOperation::Start() {
  DCHECK(thread_checker_.CalledOnValidThread());

  const brillo::Blob& public_key_spki_der =
      public_key_info_.public_key_spki_der;
  if (!public_key_info_.signature_algorithm.size()) {
    LOG(ERROR) << "The key does not support any signature algorithm";
    Complete(&completion_callback_,
             MakeStatus<CryptohomeCryptoError>(
                 CRYPTOHOME_ERR_LOC(kLocChalCredVerifyNoAlgorithm),
                 ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
                 CryptoError::CE_OTHER_CRYPTO));
    return;
  }
  const std::optional<structure::ChallengeSignatureAlgorithm>
      chosen_challenge_algorithm = ChooseChallengeAlgorithm(public_key_info_);
  if (!chosen_challenge_algorithm) {
    LOG(ERROR) << "Failed to choose verification signature challenge algorithm";
    Complete(&completion_callback_,
             MakeStatus<CryptohomeCryptoError>(
                 CRYPTOHOME_ERR_LOC(kLocChalCredVerifyNoAlgorithmChosen),
                 ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
                 CryptoError::CE_OTHER_CRYPTO));
    return;
  }
  hwsec::StatusOr<Blob> challenge = hwsec_->GetRandomBlob(kChallengeByteCount);
  if (!challenge.ok()) {
    LOG(ERROR)
        << "Failed to generate random bytes for the verification challenge: "
        << challenge.status();
    Complete(&completion_callback_,
             MakeStatus<CryptohomeCryptoError>(
                 CRYPTOHOME_ERR_LOC(kLocChalCredVerifyGetRandomFailed))
                 .Wrap(MakeStatus<CryptohomeTPMError>(
                     std::move(challenge).err_status())));
    return;
  }
  MakeKeySignatureChallenge(
      account_id_, public_key_spki_der, challenge.value(),
      *chosen_challenge_algorithm,
      base::BindOnce(
          &ChallengeCredentialsVerifyKeyOperation::OnChallengeResponse,
          weak_ptr_factory_.GetWeakPtr(), public_key_spki_der,
          *chosen_challenge_algorithm, challenge.value()));
}

void ChallengeCredentialsVerifyKeyOperation::Abort(
    CryptoStatus status [[clang::param_typestate(unconsumed)]]) {
  DCHECK(thread_checker_.CalledOnValidThread());
  Complete(&completion_callback_,
           MakeStatus<CryptohomeCryptoError>(
               CRYPTOHOME_ERR_LOC(kLocChalCredVerifyAborted))
               .Wrap(std::move(status)));
  // |this| can be already destroyed at this point.
}

void ChallengeCredentialsVerifyKeyOperation::OnChallengeResponse(
    const Blob& public_key_spki_der,
    structure::ChallengeSignatureAlgorithm challenge_algorithm,
    const Blob& challenge,
    CryptoStatusOr<std::unique_ptr<Blob>> challenge_response_status) {
  DCHECK(thread_checker_.CalledOnValidThread());
  if (!challenge_response_status.ok()) {
    LOG(ERROR) << "Verification signature challenge failed";
    Complete(&completion_callback_,
             MakeStatus<CryptohomeCryptoError>(
                 CRYPTOHOME_ERR_LOC(kLocChalCredVerifyChallengeFailed))
                 .Wrap(std::move(challenge_response_status).err_status()));
    return;
  }
  std::unique_ptr<Blob> challenge_response =
      std::move(challenge_response_status).value();
  if (!IsValidSignature(public_key_spki_der, challenge_algorithm, challenge,
                        *challenge_response)) {
    LOG(ERROR) << "Invalid signature for the verification challenge";
    Complete(&completion_callback_,
             MakeStatus<CryptohomeCryptoError>(
                 CRYPTOHOME_ERR_LOC(kLocChalCredVerifyInvalidSignature),
                 ErrorActionSet(PrimaryAction::kIncorrectAuth),
                 CryptoError::CE_OTHER_CRYPTO));
    return;
  }
  Complete(&completion_callback_, OkStatus<CryptohomeCryptoError>());
}

}  // namespace cryptohome
