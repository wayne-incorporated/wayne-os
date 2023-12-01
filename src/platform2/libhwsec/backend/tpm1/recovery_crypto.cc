// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm1/recovery_crypto.h"

#include <optional>
#include <utility>
#include <vector>

#include <brillo/secure_blob.h>
#include <libhwsec-foundation/crypto/big_num_util.h>
#include <libhwsec-foundation/crypto/ecdh_hkdf.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "libhwsec/backend/tpm1/static_utils.h"
#include "libhwsec/error/tpm1_error.h"
#include "libhwsec/overalls/overalls.h"
#include "libhwsec/status.h"
#include "libhwsec/tss_utils/scoped_tss_type.h"

using hwsec_foundation::BigNumToSecureBlob;
using hwsec_foundation::ComputeEcdhSharedSecretPoint;
using hwsec_foundation::CreateBigNumContext;
using hwsec_foundation::CreateSecureRandomBlob;
using hwsec_foundation::ScopedBN_CTX;
using hwsec_foundation::SecureBlobToBigNum;
using hwsec_foundation::Sha256;
using hwsec_foundation::status::MakeStatus;

namespace hwsec {

namespace {

// Size of the auth_value blob to be randomly generated.
//
// The choice of this constant is dictated by the desire to provide sufficient
// amount of entropy as the authorization secret for the TPM_Seal command (but
// with taking into account that this authorization value is hashed by SHA-1
// by Trousers anyway).
constexpr int kAuthValueSizeBytes = 32;

// Creates a DER encoded RSA public key given a serialized TPM_PUBKEY.
//
// Parameters
//   public_key - A serialized TPM_PUBKEY as returned by Tspi_Key_GetPubKey.
//   public_key_der - The same public key in DER encoded form.
StatusOr<brillo::Blob> ConvertPublicKeyToDER(overalls::Overalls& overalls,
                                             const brillo::Blob& public_key) {
  ASSIGN_OR_RETURN(const crypto::ScopedRSA& rsa,
                   ParseRsaFromTpmPubkeyBlob(overalls, public_key),
                   _.WithStatus<TPMError>("Failed to parse RSA public key"));

  int der_length = i2d_RSA_PUBKEY(rsa.get(), nullptr);
  if (der_length < 0) {
    return MakeStatus<TPMError>(
        "Failed to DER-encode public key using SubjectPublicKeyInfo",
        TPMRetryAction::kNoRetry);
  }

  brillo::Blob public_key_der(der_length);
  uint8_t* buffer = public_key_der.data();
  der_length = i2d_RSA_PUBKEY(rsa.get(), &buffer);
  if (der_length < 0) {
    return MakeStatus<TPMError>(
        "Failed to DER-encode public key using SubjectPublicKeyInfo",
        TPMRetryAction::kNoRetry);
  }
  public_key_der.resize(der_length);

  return public_key_der;
}

}  // namespace

StatusOr<std::optional<brillo::SecureBlob>>
RecoveryCryptoTpm1::GenerateKeyAuthValue() {
  return CreateSecureRandomBlob(kAuthValueSizeBytes);
}

StatusOr<EncryptEccPrivateKeyResponse> RecoveryCryptoTpm1::EncryptEccPrivateKey(
    const EncryptEccPrivateKeyRequest& request) {
  if (request.own_key_pair == nullptr) {
    return MakeStatus<TPMError>("The key pair cannot be null",
                                TPMRetryAction::kNoRetry);
  }

  const BIGNUM* own_priv_key_bn =
      EC_KEY_get0_private_key(request.own_key_pair.get());
  if (!own_priv_key_bn || !request.ec.IsScalarValid(*own_priv_key_bn)) {
    return MakeStatus<TPMError>("Scalar is not valid",
                                TPMRetryAction::kNoRetry);
  }
  // Convert one's own private key to blob.
  brillo::SecureBlob own_priv_key;
  if (!BigNumToSecureBlob(*own_priv_key_bn, request.ec.ScalarSizeInBytes(),
                          &own_priv_key)) {
    return MakeStatus<TPMError>("Failed to convert BIGNUM to SecureBlob",
                                TPMRetryAction::kNoRetry);
  }

  // If auth_value is not provided, one's own private key will not be sealed
  // and if auth_value is provided, one's own private key will be sealed.
  if (!request.auth_value.has_value()) {
    return EncryptEccPrivateKeyResponse{
        .encrypted_own_priv_key =
            brillo::Blob(own_priv_key.begin(), own_priv_key.end()),
    };
  }

  OperationPolicySetting policy = {
      .device_config_settings =
          DeviceConfigSettings{
              .current_user =
                  DeviceConfigSettings::CurrentUserSetting{
                      .username = std::nullopt,
                  },
          },
      .permission = Permission{.auth_value = request.auth_value},
  };

  OperationPolicySetting extended_policy = {
      .device_config_settings =
          DeviceConfigSettings{
              .current_user =
                  DeviceConfigSettings::CurrentUserSetting{
                      .username = request.current_user,
                  },
          },
      .permission = Permission{.auth_value = request.auth_value},
  };

  ASSIGN_OR_RETURN(brillo::Blob encrypted_own_priv_key,
                   sealing_.Seal(policy, own_priv_key),
                   _.WithStatus<TPMError>(
                       "Failed to seal to private key with first policy"));

  ASSIGN_OR_RETURN(brillo::Blob extended_pcr_bound_own_priv_key,
                   sealing_.Seal(extended_policy, own_priv_key),
                   _.WithStatus<TPMError>(
                       "Failed to seal to private key with second policy"));

  return EncryptEccPrivateKeyResponse{
      .encrypted_own_priv_key = encrypted_own_priv_key,
      .extended_pcr_bound_own_priv_key = extended_pcr_bound_own_priv_key,
  };
}

StatusOr<crypto::ScopedEC_POINT>
RecoveryCryptoTpm1::GenerateDiffieHellmanSharedSecret(
    const GenerateDhSharedSecretRequest& request) {
  if (request.others_pub_point == nullptr) {
    return MakeStatus<TPMError>("The public point cannot be null",
                                TPMRetryAction::kNoRetry);
  }

  ScopedBN_CTX context = CreateBigNumContext();
  if (!context.get()) {
    return MakeStatus<TPMError>("Failed to allocate BN_CTX structure",
                                TPMRetryAction::kNoRetry);
  }

  // Unseal crypto secret with auth_value
  brillo::SecureBlob unencrypted_own_priv_key;

  // if TPM is locked to single user, extended_pcr_bound_own_priv_key will be
  // used.
  ASSIGN_OR_RETURN(bool is_current_user_set, config_.IsCurrentUserSet(),
                   _.WithStatus<TPMError>("Failed to get current user status"));

  // If auth_value is not provided, one's own private key will not be unsealed
  // and if auth_value is provided, one's own private key will be unsealed.
  if (!request.auth_value.has_value()) {
    unencrypted_own_priv_key =
        brillo::SecureBlob(request.encrypted_own_priv_key);
  } else {
    brillo::Blob encrypted_own_priv_key =
        is_current_user_set ? request.extended_pcr_bound_own_priv_key
                            : request.encrypted_own_priv_key;

    OperationPolicy policy{
        .device_configs = DeviceConfigs{DeviceConfig::kCurrentUser},
        .permission = Permission{.auth_value = request.auth_value},
    };

    ASSIGN_OR_RETURN(unencrypted_own_priv_key,
                     sealing_.Unseal(policy, encrypted_own_priv_key,
                                     Sealing::UnsealOptions{}),
                     _.WithStatus<TPMError>("Failed to unseal"));
  }

  crypto::ScopedBIGNUM unencrypted_own_priv_key_bn =
      SecureBlobToBigNum(unencrypted_own_priv_key);
  if (!unencrypted_own_priv_key_bn) {
    return MakeStatus<TPMError>(
        "Failed to convert unencrypted_own_priv_key to BIGNUM",
        TPMRetryAction::kNoRetry);
  }

  // Calculate the shared secret from one's own private key and the other
  // party's public key
  crypto::ScopedEC_POINT point_dh = ComputeEcdhSharedSecretPoint(
      request.ec, *request.others_pub_point, *unencrypted_own_priv_key_bn);
  if (!point_dh) {
    return MakeStatus<TPMError>(
        "Failed to compute shared point from others_pub_point and "
        "unencrypted_own_priv_key_bn",
        TPMRetryAction::kNoRetry);
  }

  return point_dh;
}

StatusOr<std::optional<RecoveryCryptoRsaKeyPair>>
RecoveryCryptoTpm1::GenerateRsaKeyPair() {
  ASSIGN_OR_RETURN(
      KeyManagement::CreateKeyResult created_key,
      key_management_.CreateKey(OperationPolicySetting{}, KeyAlgoType::kRsa,
                                KeyManagement::LoadKeyOptions{},
                                KeyManagement::CreateKeyOptions{
                                    .allow_sign = true,
                                }),
      _.WithStatus<TPMError>("Failed to create key"));

  ASSIGN_OR_RETURN(const KeyTpm1& key_data,
                   key_management_.GetKeyData(created_key.key.GetKey()));

  const brillo::Blob& pubkey_blob = key_data.cache.pubkey_blob;

  ASSIGN_OR_RETURN(
      brillo::Blob public_key_der,
      ConvertPublicKeyToDER(overalls_, pubkey_blob),
      _.WithStatus<TPMError>("Failed to convert public key to der"));

  return RecoveryCryptoRsaKeyPair{
      .encrypted_rsa_private_key = std::move(created_key).key_blob,
      .rsa_public_key_spki_der = std::move(public_key_der),
  };
}

StatusOr<std::optional<brillo::Blob>> RecoveryCryptoTpm1::SignRequestPayload(
    const brillo::Blob& encrypted_rsa_private_key,
    const brillo::Blob& request_payload) {
  ASSIGN_OR_RETURN(
      ScopedKey key,
      key_management_.LoadKey(OperationPolicy{}, encrypted_rsa_private_key,
                              KeyManagement::LoadKeyOptions{}),
      _.WithStatus<TPMError>("Failed to load encrypted RSA private key"));

  ASSIGN_OR_RETURN(
      brillo::Blob signature,
      signing_.Sign(
          key.GetKey(), request_payload,
          SigningOptions{
              .digest_algorithm = DigestAlgorithm::kSha256,
              .rsa_padding_scheme = SigningOptions::RsaPaddingScheme::kPkcs1v15,
          }));

  return signature;
}

}  // namespace hwsec
