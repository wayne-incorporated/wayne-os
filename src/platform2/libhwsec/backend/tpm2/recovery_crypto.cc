// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "libhwsec/backend/tpm2/recovery_crypto.h"

#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <libhwsec-foundation/crypto/big_num_util.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <trunks/hmac_session.h>
#include <trunks/openssl_utility.h>
#include <trunks/policy_session.h>
#include <trunks/tpm_utility.h>

#include "libhwsec/error/tpm2_error.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/operation_policy.h"

using hwsec_foundation::BigNumToSecureBlob;
using hwsec_foundation::CreateBigNum;
using hwsec_foundation::CreateBigNumContext;
using hwsec_foundation::EllipticCurve;
using hwsec_foundation::ScopedBN_CTX;
using hwsec_foundation::status::MakeStatus;

namespace hwsec {

namespace {

StatusOr<std::vector<std::string>> GetCurrentUserPolicyDigests(
    ConfigTpm2& config, const std::string& current_user) {
  ASSIGN_OR_RETURN(
      const std::string& digest,
      config.GetPolicyDigest(OperationPolicySetting{
          .device_config_settings =
              DeviceConfigSettings{
                  .current_user =
                      DeviceConfigSettings::CurrentUserSetting{
                          .username = std::nullopt,
                      },
              }}),
      _.WithStatus<TPMError>(
          "Failed to convert prior login setting to policy digest"));

  ASSIGN_OR_RETURN(
      const std::string& extend_digest,
      config.GetPolicyDigest(OperationPolicySetting{
          .device_config_settings =
              DeviceConfigSettings{
                  .current_user =
                      DeviceConfigSettings::CurrentUserSetting{
                          .username = current_user,
                      },
              }}),
      _.WithStatus<TPMError>(
          "Failed to convert current user setting to policy digest"));

  return std::vector<std::string>{digest, extend_digest};
}

}  // namespace

StatusOr<std::optional<brillo::SecureBlob>>
RecoveryCryptoTpm2::GenerateKeyAuthValue() {
  // This operation is intentionally not implemented on TPM 2.0.
  return std::nullopt;
}

StatusOr<EncryptEccPrivateKeyResponse> RecoveryCryptoTpm2::EncryptEccPrivateKey(
    const EncryptEccPrivateKeyRequest& request) {
  ScopedBN_CTX bn_context = CreateBigNumContext();
  if (!bn_context.get()) {
    return MakeStatus<TPMError>("Failed to allocate BN_CTX structure",
                                TPMRetryAction::kNoRetry);
  }

  if (!request.own_key_pair.get()) {
    return MakeStatus<TPMError>("Key pair cannot be null",
                                TPMRetryAction::kNoRetry);
  }

  const BIGNUM* own_priv_key_bn =
      EC_KEY_get0_private_key(request.own_key_pair.get());
  if (!own_priv_key_bn) {
    return MakeStatus<TPMError>("Failed to get own_priv_key_bn",
                                TPMRetryAction::kNoRetry);
  }
  if (!request.ec.IsScalarValid(*own_priv_key_bn)) {
    return MakeStatus<TPMError>("Scalar is not valid",
                                TPMRetryAction::kNoRetry);
  }
  // Convert own private key to blob.
  brillo::SecureBlob own_priv_key;
  if (!BigNumToSecureBlob(*own_priv_key_bn, request.ec.ScalarSizeInBytes(),
                          &own_priv_key)) {
    return MakeStatus<TPMError>("Failed to convert BIGNUM to SecureBlob",
                                TPMRetryAction::kNoRetry);
  }

  const EC_POINT* pub_point =
      EC_KEY_get0_public_key(request.own_key_pair.get());
  if (!pub_point) {
    return MakeStatus<TPMError>("Failed to get pub_point",
                                TPMRetryAction::kNoRetry);
  }
  crypto::ScopedBIGNUM pub_point_x_bn = CreateBigNum(),
                       pub_point_y_bn = CreateBigNum();
  if (!pub_point_x_bn || !pub_point_y_bn) {
    return MakeStatus<TPMError>("Failed to allocate BIGNUM",
                                TPMRetryAction::kNoRetry);
  }
  if (!request.ec.GetAffineCoordinates(*pub_point, bn_context.get(),
                                       pub_point_x_bn.get(),
                                       pub_point_y_bn.get())) {
    return MakeStatus<TPMError>("Failed to get destination share x coordinate",
                                TPMRetryAction::kNoRetry);
  }
  brillo::SecureBlob pub_point_x;
  if (!BigNumToSecureBlob(*pub_point_x_bn, MAX_ECC_KEY_BYTES, &pub_point_x)) {
    return MakeStatus<TPMError>("Failed to convert BIGNUM to SecureBlob",
                                TPMRetryAction::kNoRetry);
  }
  brillo::SecureBlob pub_point_y;
  if (!BigNumToSecureBlob(*pub_point_y_bn, MAX_ECC_KEY_BYTES, &pub_point_y)) {
    return MakeStatus<TPMError>("Failed to convert BIGNUM to SecureBlob",
                                TPMRetryAction::kNoRetry);
  }

  // Translate EllipticCurve::CurveType to trunks curveID
  trunks::TPM_ECC_CURVE tpm_curve_id = trunks::TPM_ECC_NONE;
  switch (request.ec.GetCurveType()) {
    case EllipticCurve::CurveType::kPrime256:
      tpm_curve_id = trunks::TPM_ECC_NIST_P256;
      break;
    case EllipticCurve::CurveType::kPrime384:
      tpm_curve_id = trunks::TPM_ECC_NIST_P384;
      break;
    case EllipticCurve::CurveType::kPrime521:
      tpm_curve_id = trunks::TPM_ECC_NIST_P521;
      break;
  }
  if (tpm_curve_id == trunks::TPM_ECC_NONE) {
    return MakeStatus<TPMError>("Invalid tpm2 curve id",
                                TPMRetryAction::kNoRetry);
  }

  if (request.auth_value.has_value()) {
    return MakeStatus<TPMError>(
        "TPM2.0 don't support auth value for EncryptEccPrivateKey",
        TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(std::vector<std::string> policy_digests,
                   GetCurrentUserPolicyDigests(config_, request.current_user));

  // Start a trial policy session for sealing the secret value.
  std::unique_ptr<trunks::PolicySession> trial_session =
      context_.GetTrunksFactory().GetTrialSession();

  RETURN_IF_ERROR(MakeStatus<TPM2Error>(trial_session->StartUnboundSession(
                      /*salted=*/false, /*enable_encryption=*/false)))
      .WithStatus<TPMError>("Failed to start trial session");

  // Apply PolicyOR for restricting to the disjunction of the specified sets of
  // PCR restrictions.
  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(trial_session->PolicyOR(policy_digests)))
      .WithStatus<TPMError>(
          "Failed to restrict policy to logical disjunction of PCRs");

  // Obtain the resulting policy digest.
  std::string result_policy_digest;
  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(trial_session->GetDigest(&result_policy_digest)))
      .WithStatus<TPMError>("Failed to get policy digest");

  // Create the TPM session.
  ASSIGN_OR_RETURN(trunks::HmacSession & hmac_session,
                   session_management_.GetOrCreateHmacSession(
                       SessionSecuritySetting::kSaltAndEncrypted),
                   _.WithStatus<TPMError>("Failed to start hmac session"));

  // Encrypt its own private key via the TPM2_Import command.
  std::string encrypted_own_priv_key_string;
  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(
          context_.GetTpmUtility().ImportECCKeyWithPolicyDigest(
              trunks::TpmUtility::AsymmetricKeyUsage::kDecryptKey, tpm_curve_id,
              pub_point_x.to_string(), pub_point_y.to_string(),
              own_priv_key.to_string(), result_policy_digest,
              hmac_session.GetDelegate(), &encrypted_own_priv_key_string)))
      .WithStatus<TPMError>("Failed to import its own private key into TPM");

  return EncryptEccPrivateKeyResponse{
      .encrypted_own_priv_key =
          brillo::BlobFromString(encrypted_own_priv_key_string),
  };
}

StatusOr<crypto::ScopedEC_POINT>
RecoveryCryptoTpm2::GenerateDiffieHellmanSharedSecret(
    const GenerateDhSharedSecretRequest& request) {
  ScopedBN_CTX bn_context = CreateBigNumContext();
  if (!bn_context.get()) {
    return MakeStatus<TPMError>("Failed to allocate BN_CTX structure",
                                TPMRetryAction::kNoRetry);
  }

  if (!request.others_pub_point.get()) {
    return MakeStatus<TPMError>("Public point cannot be null",
                                TPMRetryAction::kNoRetry);
  }

  // Obtain coordinates of the publisher public point.
  crypto::ScopedBIGNUM others_pub_point_x_bn = CreateBigNum(),
                       others_pub_point_y_bn = CreateBigNum();
  if (!others_pub_point_x_bn || !others_pub_point_y_bn) {
    return MakeStatus<TPMError>("Failed to allocate BIGNUM",
                                TPMRetryAction::kNoRetry);
  }
  if (!request.ec.GetAffineCoordinates(
          *request.others_pub_point, bn_context.get(),
          others_pub_point_x_bn.get(), others_pub_point_y_bn.get())) {
    return MakeStatus<TPMError>(
        "Failed to get the other party's public point x coordinate",
        TPMRetryAction::kNoRetry);
  }
  brillo::SecureBlob others_pub_point_x;
  if (!BigNumToSecureBlob(*others_pub_point_x_bn, MAX_ECC_KEY_BYTES,
                          &others_pub_point_x)) {
    return MakeStatus<TPMError>("Failed to convert BIGNUM to SecureBlob",
                                TPMRetryAction::kNoRetry);
  }
  brillo::SecureBlob others_pub_point_y;
  if (!BigNumToSecureBlob(*others_pub_point_y_bn, MAX_ECC_KEY_BYTES,
                          &others_pub_point_y)) {
    return MakeStatus<TPMError>("Failed to convert BIGNUM to SecureBlob",
                                TPMRetryAction::kNoRetry);
  }

  if (request.auth_value.has_value()) {
    return MakeStatus<TPMError>(
        "TPM2.0 don't support auth value for GenerateDiffieHellmanSharedSecret",
        TPMRetryAction::kNoRetry);
  }

  brillo::Blob key_blob = request.encrypted_own_priv_key;
  ASSIGN_OR_RETURN(
      ScopedKey key,
      key_management_.LoadKey(OperationPolicy{}, key_blob,
                              KeyManagement::LoadKeyOptions{}),
      _.WithStatus<TPMError>("Failed to load encrypted ECC private key"));

  ASSIGN_OR_RETURN(const KeyTpm2& key_data,
                   key_management_.GetKeyData(key.GetKey()));

  OperationPolicy policy{
      .device_configs = DeviceConfigs{DeviceConfig::kCurrentUser},
      .permission = Permission{.auth_value = request.auth_value},
  };

  ASSIGN_OR_RETURN(std::vector<std::string> policy_digests,
                   GetCurrentUserPolicyDigests(config_, request.current_user));

  // TODO(b/196192089): set enable_encryption to true
  ASSIGN_OR_RETURN(
      std::unique_ptr<trunks::PolicySession> session,
      config_.GetTrunksPolicySession(policy, policy_digests, /*salted=*/true,
                                     /*enable_encryption=*/false),
      _.WithStatus<TPMError>("Failed to get session for policy"));

  trunks::TPMS_ECC_POINT tpm_others_pub_point = {
      trunks::Make_TPM2B_ECC_PARAMETER(others_pub_point_x.to_string()),
      trunks::Make_TPM2B_ECC_PARAMETER(others_pub_point_y.to_string())};

  // Perform the multiplication of the destination share and the other party's
  // public point via the TPM2_ECDH_ZGen command.
  trunks::TPM2B_ECC_POINT tpm_point_dh;
  RETURN_IF_ERROR(MakeStatus<TPM2Error>(context_.GetTpmUtility().ECDHZGen(
                      key_data.key_handle,
                      trunks::Make_TPM2B_ECC_POINT(tpm_others_pub_point),
                      session->GetDelegate(), &tpm_point_dh)))
      .WithStatus<TPMError>("Failed to call ECDH_ZGen");

  // Return the point after converting it from the TPM representation.
  crypto::ScopedEC_POINT point_dh = request.ec.CreatePoint();
  if (!point_dh) {
    return MakeStatus<TPMError>("Failed to allocate EC_POINT",
                                TPMRetryAction::kNoRetry);
  }

  if (!trunks::TpmToOpensslEccPoint(tpm_point_dh.point, *request.ec.GetGroup(),
                                    point_dh.get())) {
    return MakeStatus<TPMError>("Failed to convert TPM ECC point",
                                TPMRetryAction::kNoRetry);
  }

  return point_dh;
}

StatusOr<std::optional<RecoveryCryptoRsaKeyPair>>
RecoveryCryptoTpm2::GenerateRsaKeyPair() {
  // This operation is intentionally not implemented on TPM 2.0.
  return std::nullopt;
}

StatusOr<std::optional<brillo::Blob>> RecoveryCryptoTpm2::SignRequestPayload(
    const brillo::Blob& encrypted_rsa_private_key,
    const brillo::Blob& request_payload) {
  // This operation is intentionally not implemented on TPM 2.0.
  return std::nullopt;
}

}  // namespace hwsec
