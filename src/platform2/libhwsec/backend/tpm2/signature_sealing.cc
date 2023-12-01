// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm2/signature_sealing.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/functional/callback_helpers.h>
#include <base/numerics/safe_conversions.h>
#include <base/rand_util.h>
#include <brillo/secure_blob.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <openssl/sha.h>
#include <trunks/tpm_utility.h>

#include "libhwsec/error/tpm2_error.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/no_default_init.h"

using brillo::BlobFromString;
using brillo::BlobToString;
using hwsec_foundation::status::MakeStatus;
using trunks::TPM_ALG_ID;
using trunks::TPM_ALG_NULL;
using trunks::TPM_RC;
using trunks::TPM_RC_SUCCESS;

namespace hwsec {

using Algorithm = SignatureSealing::Algorithm;

namespace {

// Obtains the TPM 2.0 signature scheme and hashing algorithms that correspond
// to the provided challenge signature algorithm.
struct AlgorithmDetail {
  NoDefault<TPM_ALG_ID> scheme;
  NoDefault<TPM_ALG_ID> hash_alg;
};

StatusOr<AlgorithmDetail> GetAlgIdsByAlgorithm(Algorithm algorithm) {
  switch (algorithm) {
    case Algorithm::kRsassaPkcs1V15Sha1:
      return AlgorithmDetail{
          .scheme = trunks::TPM_ALG_RSASSA,
          .hash_alg = trunks::TPM_ALG_SHA1,
      };
    case Algorithm::kRsassaPkcs1V15Sha256:
      return AlgorithmDetail{
          .scheme = trunks::TPM_ALG_RSASSA,
          .hash_alg = trunks::TPM_ALG_SHA256,
      };
    case Algorithm::kRsassaPkcs1V15Sha384:
      return AlgorithmDetail{
          .scheme = trunks::TPM_ALG_RSASSA,
          .hash_alg = trunks::TPM_ALG_SHA384,
      };
    case Algorithm::kRsassaPkcs1V15Sha512:
      return AlgorithmDetail{
          .scheme = trunks::TPM_ALG_RSASSA,
          .hash_alg = trunks::TPM_ALG_SHA512,
      };
  }
  return MakeStatus<TPMError>("Unknown signature algorithm",
                              TPMRetryAction::kNoRetry);
}

StatusOr<AlgorithmDetail> ChooseAlgorithm(
    const std::vector<Algorithm>& key_algorithms) {
  // Choose the algorithm. Respect the input's algorithm prioritization, with
  // the exception of considering SHA-1 as the least preferred option.
  std::optional<AlgorithmDetail> sha1_fallback;

  for (Algorithm algorithm : key_algorithms) {
    if (StatusOr<AlgorithmDetail> detail = GetAlgIdsByAlgorithm(algorithm);
        detail.ok()) {
      if (detail->hash_alg == trunks::TPM_ALG_SHA1) {
        sha1_fallback = std::move(detail).value();
        continue;
      }
      return detail;
    }
  }

  if (sha1_fallback.has_value()) {
    return sha1_fallback.value();
  }

  return MakeStatus<TPMError>("No supported signature algorithm",
                              TPMRetryAction::kNoRetry);
}

}  // namespace

StatusOr<SignatureSealedData> SignatureSealingTpm2::Seal(
    const std::vector<OperationPolicySetting>& policies,
    const brillo::SecureBlob& unsealed_data,
    const brillo::Blob& public_key_spki_der,
    const std::vector<Algorithm>& key_algorithms) {
  // Drop the existing challenge if we have any.
  current_challenge_data_ = std::nullopt;

  ASSIGN_OR_RETURN(const AlgorithmDetail& algorithm,
                   ChooseAlgorithm(key_algorithms));

  if (policies.empty()) {
    return MakeStatus<TPMError>("No policy for signature sealing",
                                TPMRetryAction::kNoRetry);
  }

  std::vector<std::string> policy_digests;
  for (const OperationPolicySetting& policy : policies) {
    if (policy.permission.auth_value.has_value()) {
      return MakeStatus<TPMError>("Unsupported policy",
                                  TPMRetryAction::kNoRetry);
    }

    ASSIGN_OR_RETURN(
        const std::string& digest, config_.GetPolicyDigest(policy),
        _.WithStatus<TPMError>("Failed to convert setting to PCR value"));

    policy_digests.push_back(digest);
  }

  // Load the protection public key onto the TPM.
  ASSIGN_OR_RETURN(
      ScopedKey key,
      key_management_.LoadPublicKeyFromSpki(
          public_key_spki_der, algorithm.scheme, algorithm.hash_alg),
      _.WithStatus<TPMError>("Failed to load protection key"));

  ASSIGN_OR_RETURN(const KeyTpm2& key_data,
                   key_management_.GetKeyData(key.GetKey()));

  std::string key_name;
  RETURN_IF_ERROR(MakeStatus<TPM2Error>(context_.GetTpmUtility().GetKeyName(
                      key_data.key_handle, &key_name)))
      .WithStatus<TPMError>("Failed to get key name");

  // Start a trial policy session for sealing the secret value.
  std::unique_ptr<trunks::PolicySession> policy_session =
      context_.GetTrunksFactory().GetTrialSession();

  RETURN_IF_ERROR(MakeStatus<TPM2Error>(policy_session->StartUnboundSession(
                      /*salted=*/true, /*enable_encryption=*/false)))
      .WithStatus<TPMError>("Failed to start trial session");

  // Apply PolicyOR for restricting to the disjunction of the specified sets of
  // PCR restrictions.
  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(policy_session->PolicyOR(policy_digests)))
      .WithStatus<TPMError>(
          "Failed to restrict policy to logical disjunction of PCRs");

  // Start a TPM authorization session.
  ASSIGN_OR_RETURN(trunks::HmacSession & hmac_session,
                   session_management_.GetOrCreateHmacSession(
                       SessionSecuritySetting::kSaltAndEncrypted),
                   _.WithStatus<TPMError>("Failed to start hmac session"));

  // Update the policy with an empty signature that refers to the public key.
  trunks::TPMT_SIGNATURE signature;
  memset(&signature, 0, sizeof(trunks::TPMT_SIGNATURE));
  signature.sig_alg = algorithm.scheme;
  signature.signature.rsassa.hash = algorithm.hash_alg;
  signature.signature.rsassa.sig =
      trunks::Make_TPM2B_PUBLIC_KEY_RSA(std::string());

  RETURN_IF_ERROR(MakeStatus<TPM2Error>(policy_session->PolicySigned(
                      key_data.key_handle, key_name, /*nonce=*/std::string(),
                      /*cp_hash=*/std::string(), /*policy_ref=*/std::string(),
                      /*expiration=*/0, signature, hmac_session.GetDelegate())))
      .WithStatus<TPMError>(
          "Failed to restrict policy to signature with the public key");

  // Obtain the resulting policy digest.
  std::string result_policy_digest;
  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(policy_session->GetDigest(&result_policy_digest)))
      .WithStatus<TPMError>("Failed to get policy digest");

  if (result_policy_digest.size() != SHA256_DIGEST_LENGTH) {
    return MakeStatus<TPMError>("Unexpected policy digest size",
                                TPMRetryAction::kNoRetry);
  }

  // Seal the secret value.
  std::string sealed_value;
  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(context_.GetTpmUtility().SealData(
          unsealed_data.to_string(), result_policy_digest, /*auth_value=*/"",
          /*require_admin_with_policy=*/true, hmac_session.GetDelegate(),
          &sealed_value)))
      .WithStatus<TPMError>("Failed to seal secret data");

  std::vector<Tpm2PolicyDigest> pcr_digests;
  for (const std::string& digest : policy_digests) {
    pcr_digests.push_back(Tpm2PolicyDigest{.digest = BlobFromString(digest)});
  }

  return Tpm2PolicySignedData{
      .public_key_spki_der = public_key_spki_der,
      .srk_wrapped_secret = BlobFromString(sealed_value),
      .scheme = algorithm.scheme,
      .hash_alg = algorithm.hash_alg,
      .pcr_policy_digests = std::move(pcr_digests),
  };
}

StatusOr<SignatureSealingTpm2::ChallengeResult> SignatureSealingTpm2::Challenge(
    const OperationPolicy& policy,
    const SignatureSealedData& sealed_data,
    const brillo::Blob& public_key_spki_der,
    const std::vector<Algorithm>& key_algorithms) {
  // Validate the parameters.
  auto* sealed_data_ptr = std::get_if<Tpm2PolicySignedData>(&sealed_data);
  if (!sealed_data_ptr) {
    return MakeStatus<TPMError>(
        "Sealed data is empty or uses unexpected method",
        TPMRetryAction::kNoRetry);
  }
  const Tpm2PolicySignedData& data = *sealed_data_ptr;
  if (data.public_key_spki_der.empty()) {
    return MakeStatus<TPMError>("Empty public key", TPMRetryAction::kNoRetry);
  }
  if (data.srk_wrapped_secret.empty()) {
    return MakeStatus<TPMError>("Empty SRK wrapped secret",
                                TPMRetryAction::kNoRetry);
  }
  if (!data.scheme.has_value()) {
    return MakeStatus<TPMError>("Empty scheme", TPMRetryAction::kNoRetry);
  }
  if (!data.hash_alg.has_value()) {
    return MakeStatus<TPMError>("Empty hash algorithm",
                                TPMRetryAction::kNoRetry);
  }

  if (data.pcr_policy_digests.empty()) {
    return MakeStatus<TPMError>("Empty PCR policy digests",
                                TPMRetryAction::kNoRetry);
  }

  for (const Tpm2PolicyDigest& digest : data.pcr_policy_digests) {
    if (digest.digest.empty()) {
      return MakeStatus<TPMError>("Empty PCR policy digest",
                                  TPMRetryAction::kNoRetry);
    }
    if (digest.digest.size() != SHA256_DIGEST_LENGTH) {
      return MakeStatus<TPMError>("Invalid policy digest size",
                                  TPMRetryAction::kNoRetry);
    }
  }

  if (data.public_key_spki_der != public_key_spki_der) {
    return MakeStatus<TPMError>("Wrong subject public key info",
                                TPMRetryAction::kNoRetry);
  }
  if (!base::IsValueInRangeForNumericType<TPM_ALG_ID>(data.scheme.value())) {
    return MakeStatus<TPMError>("Failed to parse signature scheme",
                                TPMRetryAction::kNoRetry);
  }
  const TPM_ALG_ID scheme = static_cast<TPM_ALG_ID>(data.scheme.value());
  if (!base::IsValueInRangeForNumericType<TPM_ALG_ID>(data.hash_alg.value())) {
    return MakeStatus<TPMError>("Failed to parse signature hash algorithm",
                                TPMRetryAction::kNoRetry);
  }
  const TPM_ALG_ID hash_alg = static_cast<TPM_ALG_ID>(data.hash_alg.value());

  std::optional<Algorithm> algorithm;
  for (Algorithm algo : key_algorithms) {
    if (StatusOr<AlgorithmDetail> detail = GetAlgIdsByAlgorithm(algo);
        detail.ok()) {
      if (detail->scheme == scheme && detail->hash_alg == hash_alg) {
        algorithm = algo;
        break;
      }
    }
  }

  if (!algorithm.has_value()) {
    return MakeStatus<TPMError>("Key doesn't support required algorithm",
                                TPMRetryAction::kNoRetry);
  }

  // Update the policy with the disjunction of their policy digests.
  // Note: The order of items in this vector is important, it must match the
  // order used in the Seal() function, and should never change due to backwards
  // compatibility.
  std::vector<std::string> pcr_policy_digests;
  for (const Tpm2PolicyDigest& digest : data.pcr_policy_digests) {
    pcr_policy_digests.push_back(BlobToString(digest.digest));
  }

  // Start a policy session that will be used for obtaining the TPM nonce and
  // unsealing the secret value.
  ASSIGN_OR_RETURN(std::unique_ptr<trunks::PolicySession> session,
                   config_.GetTrunksPolicySession(policy, pcr_policy_digests,
                                                  /*salted=*/true,
                                                  /*enable_encryption=*/false),
                   _.WithStatus<TPMError>("Failed to get session for policy"));

  // Obtain the TPM nonce.
  std::string tpm_nonce;
  if (!session->GetDelegate()->GetTpmNonce(&tpm_nonce)) {
    return MakeStatus<TPMError>("Failed to obtaining TPM nonce",
                                TPMRetryAction::kNoRetry);
  }

  const brillo::Blob expiration_blob(4);  // zero expiration (4-byte integer)
  brillo::Blob challenge_value =
      brillo::CombineBlobs({BlobFromString(tpm_nonce), expiration_blob});

  ChallengeID challenge_id = static_cast<ChallengeID>(base::RandUint64());

  // We currently only allow one active challenge.
  current_challenge_data_ = InternalChallengeData{
      .challenge_id = challenge_id,
      .srk_wrapped_secret = data.srk_wrapped_secret,
      .public_key_spki_der = data.public_key_spki_der,
      .scheme = scheme,
      .hash_alg = hash_alg,
      .session = std::move(session),
      .session_nonce = tpm_nonce,
  };

  return ChallengeResult{
      .challenge_id = challenge_id,
      .algorithm = algorithm.value(),
      .challenge = std::move(challenge_value),
  };
}

StatusOr<brillo::SecureBlob> SignatureSealingTpm2::Unseal(
    ChallengeID challenge, const brillo::Blob& challenge_response) {
  if (!current_challenge_data_.has_value()) {
    return MakeStatus<TPMError>("No valid challenge data",
                                TPMRetryAction::kNoRetry);
  }

  const InternalChallengeData& challenge_data = current_challenge_data_.value();

  if (challenge != challenge_data.challenge_id) {
    return MakeStatus<TPMError>("Challenge ID mismatch",
                                TPMRetryAction::kNoRetry);
  }

  // Start a TPM authorization session.
  ASSIGN_OR_RETURN(trunks::HmacSession & hmac_session,
                   session_management_.GetOrCreateHmacSession(
                       SessionSecuritySetting::kSaltAndEncrypted),
                   _.WithStatus<TPMError>("Failed to start hmac session"));

  // Load the protection public key onto the TPM.
  ASSIGN_OR_RETURN(ScopedKey key,
                   key_management_.LoadPublicKeyFromSpki(
                       challenge_data.public_key_spki_der,
                       challenge_data.scheme, challenge_data.hash_alg),
                   _.WithStatus<TPMError>("Failed to load protection key"));

  ASSIGN_OR_RETURN(const KeyTpm2& key_data,
                   key_management_.GetKeyData(key.GetKey()));

  std::string key_name;
  RETURN_IF_ERROR(MakeStatus<TPM2Error>(context_.GetTpmUtility().GetKeyName(
                      key_data.key_handle, &key_name)))
      .WithStatus<TPMError>("Failed to get key name");

  // Update the policy with the signature.
  trunks::TPMT_SIGNATURE signature;
  memset(&signature, 0, sizeof(trunks::TPMT_SIGNATURE));
  signature.sig_alg = challenge_data.scheme;
  signature.signature.rsassa.hash = challenge_data.hash_alg;
  signature.signature.rsassa.sig =
      trunks::Make_TPM2B_PUBLIC_KEY_RSA(BlobToString(challenge_response));

  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(challenge_data.session->PolicySigned(
          key_data.key_handle, key_name, challenge_data.session_nonce,
          /*cp_hash=*/std::string(), /*policy_ref=*/std::string(),
          /*expiration=*/0, signature, hmac_session.GetDelegate())))
      .WithStatus<TPMError>(
          "Failed to restrict policy to signature with the public key");

  // Obtain the resulting policy digest.
  std::string policy_digest;
  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(challenge_data.session->GetDigest(&policy_digest)))
      .WithStatus<TPMError>("Failed to get policy digest");

  // Unseal the secret value.
  std::string unsealed_value_string;
  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(context_.GetTpmUtility().UnsealData(
          BlobToString(challenge_data.srk_wrapped_secret),
          challenge_data.session->GetDelegate(), &unsealed_value_string)))
      .WithStatus<TPMError>("Failed to seal secret data");

  // Unseal succeeded, remove the internal data.
  current_challenge_data_ = std::nullopt;

  return brillo::SecureBlob(unsealed_value_string);
}

}  // namespace hwsec
