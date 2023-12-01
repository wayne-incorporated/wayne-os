// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/cryptorecovery/recovery_crypto_impl.h"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/system/sys_info.h>
#include <brillo/cryptohome.h>
#include <brillo/secure_blob.h>
#include <brillo/udev/udev_device.h>
#include <chromeos-config/libcros_config/cros_config.h>
#include <libhwsec-foundation/crypto/aes.h>
#include <libhwsec-foundation/crypto/big_num_util.h>
#include <libhwsec-foundation/crypto/ecdh_hkdf.h>
#include <libhwsec-foundation/crypto/elliptic_curve.h>
#include <libhwsec-foundation/crypto/error_util.h>
#include <libhwsec-foundation/crypto/rsa.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/status/status_chain.h>
#include <openssl/ec.h>

#include "cryptohome/crypto_error.h"
#include "cryptohome/cryptohome_common.h"
#include "cryptohome/cryptorecovery/inclusion_proof.h"
#include "cryptohome/cryptorecovery/recovery_crypto_hsm_cbor_serialization.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/filesystem_layout.h"

using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using ::hwsec_foundation::AesGcmDecrypt;
using ::hwsec_foundation::AesGcmEncrypt;
using ::hwsec_foundation::BigNumToSecureBlob;
using ::hwsec_foundation::CreateBigNum;
using ::hwsec_foundation::CreateBigNumContext;
using ::hwsec_foundation::CreateSecureRandomBlob;
using ::hwsec_foundation::EllipticCurve;
using ::hwsec_foundation::GenerateEcdhHkdfSymmetricKey;
using ::hwsec_foundation::HkdfHash;
using ::hwsec_foundation::kAesGcm256KeySize;
using ::hwsec_foundation::ScopedBN_CTX;
using ::hwsec_foundation::SecureBlobToBigNum;
using ::hwsec_foundation::status::MakeStatus;
using ::hwsec_foundation::status::OkStatus;

namespace cryptohome {
namespace cryptorecovery {

namespace {

constexpr char kDeviceUnknown[] = "UNKNOWN";
constexpr int kRecoveryIdSeedLength = 32;

brillo::SecureBlob GetRecoveryKeyHkdfInfo() {
  return brillo::SecureBlob("CryptoHome Wrapping Key");
}

brillo::SecureBlob GetMediatorShareHkdfInfo() {
  return brillo::SecureBlob(RecoveryCrypto::kMediatorShareHkdfInfoValue);
}

brillo::SecureBlob GetRequestPayloadPlainTextHkdfInfo() {
  return brillo::SecureBlob(
      RecoveryCrypto::kRequestPayloadPlainTextHkdfInfoValue);
}

brillo::SecureBlob GetResponsePayloadPlainTextHkdfInfo() {
  return brillo::SecureBlob(
      RecoveryCrypto::kResponsePayloadPlainTextHkdfInfoValue);
}

bool GenerateRecoveryRequestAssociatedData(
    const HsmPayload& hsm_payload,
    const RequestMetadata& request_meta_data,
    const CryptoRecoveryEpochResponse& epoch_response,
    RecoveryRequestAssociatedData* request_ad) {
  HsmAssociatedData hsm_associated_data;
  if (!DeserializeHsmAssociatedDataFromCbor(hsm_payload.associated_data,
                                            &hsm_associated_data)) {
    LOG(ERROR) << "Unable to deserialize hsm_payload.associated_data";
    return false;
  }
  // Log the recovery id, to be used for debugging.
  // Note: the log format should match `CrashCollector::StripRecoveryId()`.
  LOG(INFO) << "GenerateRecoveryRequestAssociatedData for recovery_id: "
            << hsm_associated_data.onboarding_meta_data.recovery_id;

  request_ad->hsm_payload = hsm_payload;
  request_ad->request_meta_data = request_meta_data;
  if (!epoch_response.has_epoch_meta_data()) {
    LOG(ERROR) << "Epoch response doesn't have epoch metadata";
    return false;
  }
  brillo::SecureBlob epoch_meta_data(epoch_response.epoch_meta_data().begin(),
                                     epoch_response.epoch_meta_data().end());
  if (!DeserializeEpochMetadataFromCbor(epoch_meta_data,
                                        &request_ad->epoch_meta_data)) {
    LOG(ERROR) << "Failed to deserialize epoch metadata from cbor";
    return false;
  }
  request_ad->request_payload_salt =
      CreateSecureRandomBlob(RecoveryCrypto::kHkdfSaltLength);
  return true;
}

bool GenerateRecoveryRequestProto(const RecoveryRequest& request,
                                  CryptoRecoveryRpcRequest* recovery_request) {
  brillo::SecureBlob request_cbor;
  if (!SerializeRecoveryRequestToCbor(request, &request_cbor)) {
    LOG(ERROR) << "Failed to serialize Recovery Request to CBOR";
    return false;
  }
  recovery_request->set_protocol_version(1);
  recovery_request->set_cbor_cryptorecoveryrequest(request_cbor.data(),
                                                   request_cbor.size());
  return true;
}

bool GetResponsePayloadFromProto(
    const CryptoRecoveryRpcResponse& recovery_response_proto,
    ResponsePayload* recovery_response) {
  if (!recovery_response_proto.has_cbor_cryptorecoveryresponse()) {
    LOG(ERROR)
        << "No cbor_cryptorecoveryresponse field in recovery_response_proto";
    return false;
  }
  brillo::SecureBlob recovery_response_cbor(
      recovery_response_proto.cbor_cryptorecoveryresponse().begin(),
      recovery_response_proto.cbor_cryptorecoveryresponse().end());
  if (!DeserializeResponsePayloadFromCbor(recovery_response_cbor,
                                          recovery_response)) {
    LOG(ERROR) << "Unable to deserialize Recovery Response from CBOR";
    return false;
  }
  return true;
}

std::string GetRlzCode() {
  constexpr char kPath[] = "/";
  constexpr char kProperty[] = "brand-code";
  std::string data;
  brillo::CrosConfig cros_config;
  if (!cros_config.GetString(kPath, kProperty, &data)) {
    return kDeviceUnknown;
  }
  return data;
}

CryptoError CryptoErrorFromRecoveryResponseError(RecoveryError response_error) {
  switch (response_error) {
    case RecoveryError::RECOVERY_ERROR_UNSPECIFIED:
      return CryptoError::CE_NONE;
    case RecoveryError::RECOVERY_ERROR_FATAL:
    case RecoveryError::RECOVERY_ERROR_AUTH:
      return CryptoError::CE_RECOVERY_FATAL;
    case RecoveryError::RECOVERY_ERROR_TRANSIENT:
    case RecoveryError::RECOVERY_ERROR_EPOCH:
    case RecoveryError::RECOVERY_ERROR_AUTH_EXPIRED:
      return CryptoError::CE_RECOVERY_TRANSIENT;
  }
}

ErrorActionSet ErrorActionSetFromRecoveryResponseError(
    RecoveryError response_error) {
  switch (response_error) {
    case RecoveryError::RECOVERY_ERROR_UNSPECIFIED:
      return {};
    case RecoveryError::RECOVERY_ERROR_FATAL:
    case RecoveryError::RECOVERY_ERROR_AUTH:
      return ErrorActionSet({PossibleAction::kFatal});
    case RecoveryError::RECOVERY_ERROR_TRANSIENT:
    case RecoveryError::RECOVERY_ERROR_EPOCH:
    case RecoveryError::RECOVERY_ERROR_AUTH_EXPIRED:
      return ErrorActionSet({PossibleAction::kRetry});
  }
}

}  // namespace

std::unique_ptr<RecoveryCryptoImpl> RecoveryCryptoImpl::Create(
    const hwsec::RecoveryCryptoFrontend* hwsec_backend, Platform* platform) {
  DCHECK(hwsec_backend);
  ScopedBN_CTX context = CreateBigNumContext();
  if (!context.get()) {
    LOG(ERROR) << "Failed to allocate BN_CTX structure";
    return nullptr;
  }
  std::optional<EllipticCurve> ec =
      EllipticCurve::Create(kCurve, context.get());
  if (!ec) {
    LOG(ERROR) << "Failed to create EllipticCurve";
    return nullptr;
  }
  // using wrapUnique because the constructor is private and make_unique calls
  // the constructor externally
  return base::WrapUnique(
      new RecoveryCryptoImpl(std::move(*ec), hwsec_backend, platform));
}

RecoveryCryptoImpl::RecoveryCryptoImpl(
    EllipticCurve ec,
    const hwsec::RecoveryCryptoFrontend* hwsec_backend,
    Platform* platform)
    : ec_(std::move(ec)), hwsec_backend_(hwsec_backend), platform_(platform) {
  DCHECK(hwsec_backend_);
}

RecoveryCryptoImpl::~RecoveryCryptoImpl() = default;

bool RecoveryCryptoImpl::GenerateRecoveryKey(
    const crypto::ScopedEC_POINT& recovery_pub_point,
    const crypto::ScopedEC_KEY& dealer_key_pair,
    brillo::SecureBlob* recovery_key) const {
  ScopedBN_CTX context = CreateBigNumContext();
  if (!context.get()) {
    LOG(ERROR) << "Failed to allocate BN_CTX structure";
    return false;
  }

  const BIGNUM* dealer_priv_key =
      EC_KEY_get0_private_key(dealer_key_pair.get());
  if (!dealer_priv_key) {
    LOG(ERROR) << "Failed to get dealer_priv_key";
    return false;
  }
  crypto::ScopedEC_POINT point_dh =
      ec_.Multiply(*recovery_pub_point, *dealer_priv_key, context.get());
  if (!point_dh) {
    LOG(ERROR) << "Failed to perform point multiplication of "
                  "recovery_pub_point and dealer_priv_key";
    return false;
  }
  // Get point's affine X coordinate.
  crypto::ScopedBIGNUM recovery_dh_x = CreateBigNum();
  if (!recovery_dh_x) {
    LOG(ERROR) << "Failed to allocate BIGNUM";
    return false;
  }
  if (!ec_.GetAffineCoordinates(*point_dh, context.get(), recovery_dh_x.get(),
                                /*y=*/nullptr)) {
    LOG(ERROR) << "Failed to get point_dh x coordinate";
    return false;
  }

  brillo::SecureBlob hkdf_secret;
  // Convert X coordinate to fixed-size blob.
  if (!BigNumToSecureBlob(*recovery_dh_x, ec_.AffineCoordinateSizeInBytes(),
                          &hkdf_secret)) {
    LOG(ERROR) << "Failed to convert recovery_dh_x BIGNUM to SecureBlob";
    return false;
  }
  const EC_POINT* dealer_pub_point =
      EC_KEY_get0_public_key(dealer_key_pair.get());
  if (!dealer_pub_point) {
    LOG(ERROR) << "Failed to get dealer_pub_point";
    return false;
  }
  brillo::SecureBlob dealer_pub_key;
  if (!ec_.EncodeToSpkiDer(dealer_key_pair, &dealer_pub_key, context.get())) {
    LOG(ERROR) << "Failed to convert dealer_pub_key to SubjectPublicKeyInfo";
    return false;
  }
  if (!ComputeHkdfWithInfoSuffix(hkdf_secret, GetRecoveryKeyHkdfInfo(),
                                 dealer_pub_key, /*salt=*/brillo::SecureBlob(),
                                 HkdfHash::kSha256, /*result_len=*/0,
                                 recovery_key)) {
    LOG(ERROR) << "Failed to compute HKDF of recovery_dh";
    return false;
  }
  return true;
}

bool RecoveryCryptoImpl::GenerateEphemeralKey(
    brillo::SecureBlob* ephemeral_spki_der,
    brillo::SecureBlob* ephemeral_inv_spki_der) const {
  ScopedBN_CTX context = CreateBigNumContext();
  if (!context.get()) {
    LOG(ERROR) << "Failed to allocate BN_CTX structure";
    return false;
  }

  // Generate ephemeral key pair {`ephemeral_secret`, `ephemeral_pub_key`} ({x,
  // G*x}), and the inverse public key G*-x.
  crypto::ScopedBIGNUM ephemeral_priv_key_bn =
      ec_.RandomNonZeroScalar(context.get());
  if (!ephemeral_priv_key_bn) {
    LOG(ERROR) << "Failed to generate ephemeral_priv_key_bn";
    return false;
  }
  crypto::ScopedEC_POINT ephemeral_pub_point =
      ec_.MultiplyWithGenerator(*ephemeral_priv_key_bn, context.get());
  if (!ephemeral_pub_point) {
    LOG(ERROR) << "Failed to perform MultiplyWithGenerator operation for "
                  "ephemeral_priv_key_bn";
    return false;
  }
  crypto::ScopedEC_KEY ephemeral_pub_key =
      ec_.PointToEccKey(*ephemeral_pub_point);
  if (!ephemeral_pub_key) {
    LOG(ERROR) << "Failed to convert ephemeral_pub_point to an EC_KEY";
    return false;
  }
  if (!ec_.EncodeToSpkiDer(ephemeral_pub_key, ephemeral_spki_der,
                           context.get())) {
    LOG(ERROR) << "Failed to convert ephemeral_pub_point to a SecureBlob";
    return false;
  }

  if (!ec_.InvertPoint(ephemeral_pub_point.get(), context.get())) {
    LOG(ERROR) << "Failed to invert the ephemeral_pub_point";
    return false;
  }
  crypto::ScopedEC_KEY ephemeral_inv_pub_key =
      ec_.PointToEccKey(*ephemeral_pub_point);
  if (!ephemeral_inv_pub_key) {
    LOG(ERROR) << "Failed to convert ephemeral_inv_pub_key to an EC_KEY";
    return false;
  }
  if (!ec_.EncodeToSpkiDer(ephemeral_inv_pub_key, ephemeral_inv_spki_der,
                           context.get())) {
    LOG(ERROR)
        << "Failed to convert inverse ephemeral_pub_point to a SecureBlob";
    return false;
  }
  return true;
}

bool RecoveryCryptoImpl::GenerateRecoveryRequest(
    const GenerateRecoveryRequestRequest& request_param,
    CryptoRecoveryRpcRequest* recovery_request,
    brillo::SecureBlob* ephemeral_pub_key) const {
  ScopedBN_CTX context = CreateBigNumContext();
  if (!context.get()) {
    LOG(ERROR) << "Failed to allocate BN_CTX structure";
    return false;
  }

  RequestPayload request_payload;
  RecoveryRequestAssociatedData request_ad;
  if (!GenerateRecoveryRequestAssociatedData(
          request_param.hsm_payload, request_param.request_meta_data,
          request_param.epoch_response, &request_ad)) {
    LOG(ERROR) << "Failed to generate recovery request associated data";
    return false;
  }
  if (!SerializeRecoveryRequestAssociatedDataToCbor(
          request_ad, &request_payload.associated_data)) {
    LOG(ERROR)
        << "Failed to serialize recovery request associated data to cbor";
    return false;
  }

  brillo::SecureBlob epoch_pub_key;
  epoch_pub_key.assign(request_param.epoch_response.epoch_pub_key().begin(),
                       request_param.epoch_response.epoch_pub_key().end());

  crypto::ScopedEC_POINT epoch_pub_point =
      ec_.DecodeFromSpkiDer(epoch_pub_key, context.get());
  if (!epoch_pub_point) {
    LOG(ERROR) << "Failed to convert epoch_pub_key SecureBlob to EC_POINT";
    return false;
  }
  // Performs scalar multiplication of epoch_pub_point and channel_priv_key.
  // Here we don't use key_auth_value generated from GenerateKeyAuthValue()
  // because key_auth_value is unavailable and will only be recovered from the
  // decrypted response afterward
  hwsec::StatusOr<crypto::ScopedEC_POINT> shared_secret_point =
      hwsec_backend_->GenerateDiffieHellmanSharedSecret(
          hwsec::GenerateDhSharedSecretRequest{
              .ec = ec_,
              .encrypted_own_priv_key =
                  brillo::Blob(request_param.encrypted_channel_priv_key.begin(),
                               request_param.encrypted_channel_priv_key.end()),
              .extended_pcr_bound_own_priv_key = brillo::Blob(),
              .auth_value = std::nullopt,
              .current_user = *request_param.obfuscated_username,
              .others_pub_point = std::move(epoch_pub_point),
          });
  if (!shared_secret_point.ok()) {
    LOG(ERROR) << "Failed to compute shared point from epoch_pub_point and "
                  "channel_priv_key: "
               << shared_secret_point.status();
    return false;
  }
  brillo::SecureBlob aes_gcm_key;
  // The static nature of `channel_pub_key` (G*s) and `epoch_pub_key` (G*r)
  // requires the need to utilize a randomized salt value in the HKDF
  // computation.
  if (!GenerateEcdhHkdfSymmetricKey(
          ec_, *shared_secret_point.value(), request_param.channel_pub_key,
          GetRequestPayloadPlainTextHkdfInfo(), request_ad.request_payload_salt,
          kHkdfHash, kAesGcm256KeySize, &aes_gcm_key)) {
    LOG(ERROR) << "Failed to generate ECDH+HKDF sender keys for recovery "
                  "request plain text encryption";
    return false;
  }

  // Dispose shared_secret_point after used
  shared_secret_point.value().reset();

  brillo::SecureBlob ephemeral_inverse_pub_key;
  if (!GenerateEphemeralKey(ephemeral_pub_key, &ephemeral_inverse_pub_key)) {
    LOG(ERROR) << "Failed to generate Ephemeral keys";
    return false;
  }

  brillo::SecureBlob plain_text_cbor;
  RecoveryRequestPlainText plain_text;
  plain_text.ephemeral_pub_inv_key = ephemeral_inverse_pub_key;
  if (!SerializeRecoveryRequestPlainTextToCbor(plain_text, &plain_text_cbor)) {
    LOG(ERROR) << "Failed to generate Recovery Request plain text cbor";
    return false;
  }

  if (!AesGcmEncrypt(plain_text_cbor, request_payload.associated_data,
                     aes_gcm_key, &request_payload.iv, &request_payload.tag,
                     &request_payload.cipher_text)) {
    LOG(ERROR) << "Failed to perform AES-GCM encryption of plain_text_cbor for "
                  "recovery request";
    return false;
  }

  // Sign the request payload with the rsa private key
  brillo::SecureBlob request_payload_secure_blob;
  if (!SerializeRecoveryRequestPayloadToCbor(request_payload,
                                             &request_payload_secure_blob)) {
    LOG(ERROR) << "Failed to serialize Recovery Request payload";
    return false;
  }
  brillo::Blob encrypted_rsa_priv_key(
      request_param.encrypted_rsa_priv_key.begin(),
      request_param.encrypted_rsa_priv_key.end());
  brillo::Blob request_payload_blob(request_payload_secure_blob.begin(),
                                    request_payload_secure_blob.end());
  hwsec::StatusOr<std::optional<brillo::Blob>> rsa_signature =
      hwsec_backend_->SignRequestPayload(encrypted_rsa_priv_key,
                                         request_payload_blob);
  if (!rsa_signature.ok()) {
    LOG(ERROR) << "Failed to sign Recovery Request payload: "
               << rsa_signature.status();
    return false;
  }

  RecoveryRequest request;
  request.request_payload = std::move(request_payload_secure_blob);
  if (rsa_signature.value().has_value()) {
    request.rsa_signature = brillo::SecureBlob(rsa_signature.value().value());
  }
  if (!GenerateRecoveryRequestProto(request, recovery_request)) {
    LOG(ERROR) << "Failed to generate Recovery Request proto";
    return false;
  }
  return true;
}

bool RecoveryCryptoImpl::GenerateHsmPayload(
    const GenerateHsmPayloadRequest& request,
    GenerateHsmPayloadResponse* response) const {
  ScopedBN_CTX context = CreateBigNumContext();
  if (!context.get()) {
    LOG(ERROR) << "Failed to allocate BN_CTX structure";
    return false;
  }

  // Generate two shares and a secret equal to the sum.
  // Loop until the sum of two shares is non-zero (modulo order).
  crypto::ScopedEC_KEY destination_share_key_pair =
      ec_.GenerateKey(context.get());
  if (!destination_share_key_pair) {
    LOG(ERROR) << "Failed to generate destination share key pair";
    return false;
  }
  const BIGNUM* destination_share_bn =
      EC_KEY_get0_private_key(destination_share_key_pair.get());
  if (!destination_share_bn) {
    LOG(ERROR) << "Failed to generate destination_share secret";
    return false;
  }
  crypto::ScopedBIGNUM secret;
  crypto::ScopedBIGNUM mediator_share_bn;
  do {
    mediator_share_bn = ec_.RandomNonZeroScalar(context.get());
    if (!mediator_share_bn) {
      LOG(ERROR) << "Failed to generate mediator_share secret";
      return false;
    }
    secret =
        ec_.ModAdd(*mediator_share_bn, *destination_share_bn, context.get());
    if (!secret) {
      LOG(ERROR) << "Failed to perform modulo addition of mediator_share "
                    "and destination_share";
      return false;
    }
  } while (BN_is_zero(secret.get()));

  hwsec::StatusOr<std::optional<brillo::SecureBlob>> key_auth_value =
      hwsec_backend_->GenerateKeyAuthValue();
  if (!key_auth_value.ok()) {
    LOG(ERROR) << "Failed to generate key auth value: "
               << key_auth_value.status();
    return false;
  }

  hwsec::EncryptEccPrivateKeyRequest backend_request_destination_share{
      .ec = ec_,
      .own_key_pair = std::move(destination_share_key_pair),
      .auth_value = key_auth_value.value(),
      .current_user = *request.obfuscated_username,
  };
  hwsec::StatusOr<hwsec::EncryptEccPrivateKeyResponse>
      backend_response_destination_share = hwsec_backend_->EncryptEccPrivateKey(
          std::move(backend_request_destination_share));
  if (!backend_response_destination_share.ok()) {
    LOG(ERROR) << "Failed to encrypt destination share: "
               << backend_response_destination_share.status();
    return false;
  }
  response->encrypted_destination_share = brillo::SecureBlob(
      backend_response_destination_share->encrypted_own_priv_key);
  response->extended_pcr_bound_destination_share = brillo::SecureBlob(
      backend_response_destination_share->extended_pcr_bound_own_priv_key);

  crypto::ScopedEC_POINT recovery_pub_point =
      ec_.MultiplyWithGenerator(*secret, context.get());
  if (!recovery_pub_point) {
    LOG(ERROR)
        << "Failed to perform MultiplyWithGenerator operation for the secret";
    return false;
  }

  // Generate RSA key pair
  hwsec::StatusOr<std::optional<hwsec::RecoveryCryptoRsaKeyPair>> rsa_key_pair =
      hwsec_backend_->GenerateRsaKeyPair();
  if (!rsa_key_pair.ok()) {
    LOG(ERROR) << "Error creating PCR bound signing key: "
               << rsa_key_pair.status();
    return false;
  }

  brillo::SecureBlob rsa_public_key_der;
  if (rsa_key_pair.value().has_value()) {
    response->encrypted_rsa_priv_key =
        brillo::SecureBlob(rsa_key_pair.value()->encrypted_rsa_private_key);
    rsa_public_key_der =
        brillo::SecureBlob(rsa_key_pair.value()->rsa_public_key_spki_der);
  }

  // Generate channel key pair.
  crypto::ScopedEC_KEY channel_key_pair = ec_.GenerateKey(context.get());
  if (!channel_key_pair) {
    LOG(ERROR) << "Failed to generate channel key pair";
    return false;
  }
  if (!ec_.EncodeToSpkiDer(channel_key_pair, &response->channel_pub_key,
                           context.get())) {
    LOG(ERROR) << "Failed to convert channel_pub_key to SubjectPublicKeyInfo";
    return false;
  }
  // Here we don't use key_auth_value generated from GenerateKeyAuthValue()
  // because key_auth_value will be unavailable when encrypted_channel_priv_key
  // is unsealed from TPM1.2
  hwsec::EncryptEccPrivateKeyRequest backend_request_channel_priv_key{
      .ec = ec_,
      .own_key_pair = std::move(channel_key_pair),
      .auth_value = std::nullopt,
      .current_user = *request.obfuscated_username,
  };
  hwsec::StatusOr<hwsec::EncryptEccPrivateKeyResponse>
      backend_response_channel_priv_key = hwsec_backend_->EncryptEccPrivateKey(
          std::move(backend_request_channel_priv_key));
  if (!backend_response_channel_priv_key.ok()) {
    LOG(ERROR) << "Failed to encrypt channel_priv_key: "
               << backend_response_channel_priv_key.status();
    return false;
  }

  response->encrypted_channel_priv_key = brillo::SecureBlob(
      backend_response_channel_priv_key->encrypted_own_priv_key);

  crypto::ScopedEC_KEY publisher_key_pair = ec_.GenerateKey(context.get());
  if (!publisher_key_pair) {
    LOG(ERROR) << "Failed to generate publisher key pair";
    return false;
  }

  // Construct associated data for HSM payload: AD = CBOR({publisher_pub_key,
  // channel_pub_key, rsa_pub_key, onboarding_metadata}).
  if (!GenerateHsmAssociatedData(response->channel_pub_key, rsa_public_key_der,
                                 publisher_key_pair,
                                 request.onboarding_metadata,
                                 &(response->hsm_payload.associated_data))) {
    LOG(ERROR) << "Failed to generate HSM associated data cbor";
    return false;
  }

  // Generate dealer key pair.
  crypto::ScopedEC_KEY dealer_key_pair = ec_.GenerateKey(context.get());
  if (!dealer_key_pair) {
    LOG(ERROR) << "Failed to generate dealer key pair";
    return false;
  }
  // Construct plain text for HSM payload PT = CBOR({dealer_pub_key,
  // mediator_share, kav}).
  const EC_POINT* dealer_pub_point =
      EC_KEY_get0_public_key(dealer_key_pair.get());
  if (!dealer_pub_point) {
    LOG(ERROR) << "Failed to get dealer_pub_point";
    return false;
  }
  brillo::SecureBlob dealer_pub_key;
  if (!ec_.EncodeToSpkiDer(dealer_key_pair, &dealer_pub_key, context.get())) {
    LOG(ERROR) << "Failed to convert dealer_pub_key to SubjectPublicKeyInfo";
    return false;
  }
  brillo::SecureBlob mediator_share;
  if (!BigNumToSecureBlob(*mediator_share_bn, ec_.ScalarSizeInBytes(),
                          &mediator_share)) {
    LOG(ERROR) << "Failed to convert mediator_share to a SecureBlob";
    return false;
  }

  brillo::SecureBlob plain_text_cbor;
  HsmPlainText hsm_plain_text;
  hsm_plain_text.mediator_share = mediator_share;
  hsm_plain_text.dealer_pub_key = dealer_pub_key;
  if (key_auth_value.value().has_value()) {
    hsm_plain_text.key_auth_value = key_auth_value.value().value();
  }
  if (!SerializeHsmPlainTextToCbor(hsm_plain_text, &plain_text_cbor)) {
    LOG(ERROR) << "Failed to generate HSM plain text cbor";
    return false;
  }

  // Generate symmetric key for encrypting PT from (G*h)*u (where G*h is the
  // mediator public key provided as input, and u is the publisher private key).
  crypto::ScopedEC_POINT mediator_pub_point =
      ec_.DecodeFromSpkiDer(request.mediator_pub_key, context.get());
  if (!mediator_pub_point) {
    LOG(ERROR) << "Failed to convert mediator_pub_key to EC_POINT";
    return false;
  }
  const BIGNUM* publisher_priv_key =
      EC_KEY_get0_private_key(publisher_key_pair.get());
  if (!publisher_priv_key) {
    LOG(ERROR) << "Failed to get publisher_priv_key from publisher_key_pair";
    return false;
  }
  crypto::ScopedEC_POINT shared_secret_point = ComputeEcdhSharedSecretPoint(
      ec_, *mediator_pub_point, *publisher_priv_key);
  if (!shared_secret_point) {
    LOG(ERROR) << "Failed to compute shared point from mediator_pub_point and "
                  "publisher_priv_key";
    return false;
  }
  brillo::SecureBlob publisher_pub_key_blob;
  if (!ec_.EncodeToSpkiDer(publisher_key_pair, &publisher_pub_key_blob,
                           context.get())) {
    LOG(ERROR) << "Failed to convert publisher_pub_key to SubjectPublicKeyInfo";
    return false;
  }

  brillo::SecureBlob aes_gcm_key;
  // |hkdf_salt| can be empty here because the input already has a high entropy.
  // Bruteforce attacks are not an issue here and as we generate an ephemeral
  // key as input to HKDF the output will already be non-deterministic.
  if (!GenerateEcdhHkdfSymmetricKey(
          ec_, *shared_secret_point, publisher_pub_key_blob,
          GetMediatorShareHkdfInfo(),
          /*hkdf_salt=*/brillo::SecureBlob(), kHkdfHash, kAesGcm256KeySize,
          &aes_gcm_key)) {
    LOG(ERROR) << "Failed to generate ECDH+HKDF sender keys for HSM plain text "
                  "encryption";
    return false;
  }

  if (!AesGcmEncrypt(plain_text_cbor, response->hsm_payload.associated_data,
                     aes_gcm_key, &response->hsm_payload.iv,
                     &response->hsm_payload.tag,
                     &response->hsm_payload.cipher_text)) {
    LOG(ERROR) << "Failed to perform AES-GCM encryption of HSM plain text";
    return false;
  }

  // Cleanup: all intermediate secrets must be securely disposed at the end of
  // HSM payload generation.
  aes_gcm_key.clear();
  shared_secret_point.reset();
  plain_text_cbor.clear();
  mediator_share.clear();
  dealer_pub_key.clear();
  publisher_key_pair.reset();

  return GenerateRecoveryKey(recovery_pub_point, dealer_key_pair,
                             &response->recovery_key);
}

bool RecoveryCryptoImpl::RecoverDestination(
    const RecoverDestinationRequest& request,
    brillo::SecureBlob* destination_recovery_key) const {
  ScopedBN_CTX context = CreateBigNumContext();
  if (!context.get()) {
    LOG(ERROR) << "Failed to allocate BN_CTX structure";
    return false;
  }
  crypto::ScopedEC_POINT dealer_pub_point =
      ec_.DecodeFromSpkiDer(request.dealer_pub_key, context.get());
  if (!dealer_pub_point) {
    LOG(ERROR) << "Failed to convert dealer_pub_point SecureBlob to EC_POINT";
    return false;
  }
  crypto::ScopedEC_POINT mediated_point =
      ec_.DecodeFromSpkiDer(request.mediated_publisher_pub_key, context.get());
  if (!mediated_point) {
    LOG(ERROR) << "Failed to convert mediated_point SecureBlob to EC_POINT";
    return false;
  }
  // Performs addition of mediated_point and ephemeral_pub_point.
  crypto::ScopedEC_POINT ephemeral_pub_point =
      ec_.DecodeFromSpkiDer(request.ephemeral_pub_key, context.get());
  if (!ephemeral_pub_point) {
    LOG(ERROR)
        << "Failed to convert ephemeral_pub_point SecureBlob to EC_POINT";
    return false;
  }
  crypto::ScopedEC_POINT mediator_dh =
      ec_.Add(*mediated_point, *ephemeral_pub_point, context.get());
  if (!mediator_dh) {
    LOG(ERROR) << "Failed to add mediated_point and ephemeral_pub_point";
    return false;
  }

  std::optional<brillo::SecureBlob> auth_value;
  if (!request.key_auth_value.empty()) {
    auth_value = request.key_auth_value;
  }

  // Performs scalar multiplication of dealer_pub_point and destination_share.
  hwsec::GenerateDhSharedSecretRequest backend_request_destination_share{
      .ec = ec_,
      .encrypted_own_priv_key =
          brillo::Blob(request.encrypted_destination_share.begin(),
                       request.encrypted_destination_share.end()),
      .extended_pcr_bound_own_priv_key =
          brillo::Blob(request.extended_pcr_bound_destination_share.begin(),
                       request.extended_pcr_bound_destination_share.end()),
      .auth_value = auth_value,
      .current_user = *request.obfuscated_username,
      .others_pub_point = std::move(dealer_pub_point),
  };
  hwsec::StatusOr<crypto::ScopedEC_POINT> point_dh =
      hwsec_backend_->GenerateDiffieHellmanSharedSecret(
          std::move(backend_request_destination_share));
  if (!point_dh.ok()) {
    LOG(ERROR) << "Failed to perform scalar multiplication of dealer_pub_point "
                  "and destination_share: "
               << point_dh.status();
    return false;
  }
  crypto::ScopedEC_POINT point_dest =
      ec_.Add(*point_dh.value(), *mediator_dh, context.get());
  if (!point_dest) {
    LOG(ERROR)
        << "Failed to perform point addition of point_dh and mediator_dh";
    return false;
  }
  // Get point's affine X coordinate.
  crypto::ScopedBIGNUM destination_dh_x = CreateBigNum();
  if (!destination_dh_x) {
    LOG(ERROR) << "Failed to allocate BIGNUM";
    return false;
  }
  if (!ec_.GetAffineCoordinates(*point_dest, context.get(),
                                destination_dh_x.get(), /*y=*/nullptr)) {
    LOG(ERROR) << "Failed to get point_dest x coordinate";
    return false;
  }
  brillo::SecureBlob hkdf_secret;
  // Convert X coordinate to fixed-size blob.
  if (!BigNumToSecureBlob(*destination_dh_x, ec_.AffineCoordinateSizeInBytes(),
                          &hkdf_secret)) {
    LOG(ERROR) << "Failed to convert destination_dh_x BIGNUM to SecureBlob";
    return false;
  }
  if (!ComputeHkdfWithInfoSuffix(
          hkdf_secret, GetRecoveryKeyHkdfInfo(), request.dealer_pub_key,
          /*salt=*/brillo::SecureBlob(), HkdfHash::kSha256, /*result_len=*/0,
          destination_recovery_key)) {
    LOG(ERROR) << "Failed to compute HKDF of destination_dh";
    return false;
  }
  return true;
}

CryptoStatus RecoveryCryptoImpl::DecryptResponsePayload(
    const DecryptResponsePayloadRequest& request,
    HsmResponsePlainText* response_plain_text) const {
  ScopedBN_CTX context = CreateBigNumContext();
  if (!context.get()) {
    LOG(ERROR) << "Failed to allocate BN_CTX structure";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocRecoveryCryptoNoContextInDecryptResponse),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  RecoveryError resp_error_code = request.recovery_response_proto.error_code();
  if (resp_error_code != RecoveryError::RECOVERY_ERROR_UNSPECIFIED) {
    LOG(ERROR) << "Recovery response returned an error: "
               << static_cast<int>(resp_error_code);
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocRecoveryCryptoResponseErrInDecryptResponse),
        ErrorActionSetFromRecoveryResponseError(resp_error_code),
        CryptoErrorFromRecoveryResponseError(resp_error_code));
  }

  ResponsePayload recovery_response;
  if (!GetResponsePayloadFromProto(request.recovery_response_proto,
                                   &recovery_response)) {
    LOG(ERROR) << "Unable to deserialize Recovery Response from proto";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocRecoveryCryptoBadPayloadInDecryptResponse),
        ErrorActionSet(
            {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kFatal}),
        CryptoError::CE_RECOVERY_FATAL);
  }

  HsmResponseAssociatedData response_ad;
  if (!DeserializeHsmResponseAssociatedDataFromCbor(
          recovery_response.associated_data, &response_ad)) {
    LOG(ERROR) << "Unable to deserialize Response payload associated data";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocRecoveryCryptoBadADInDecryptResponse),
        ErrorActionSet(
            {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kFatal}),
        CryptoError::CE_RECOVERY_FATAL);
  }

  // Verify inclusion proof.
  if (!VerifyInclusionProof(response_ad.ledger_signed_proof,
                            request.ledger_info)) {
    LOG(ERROR) << "Unable to verify inclusion proof";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocRecoveryCryptoBadLedgerSignedProof),
        ErrorActionSet(
            {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kFatal}),
        CryptoError::CE_RECOVERY_FATAL);
  }

  if (!request.epoch_response.has_epoch_pub_key()) {
    LOG(ERROR) << "Epoch response doesn't have epoch public key";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocRecoveryCryptoNoEpochKeyInDecryptResponse),
        ErrorActionSet(
            {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kFatal}),
        CryptoError::CE_RECOVERY_FATAL);
  }
  brillo::SecureBlob epoch_pub_key(request.epoch_response.epoch_pub_key());
  crypto::ScopedEC_POINT epoch_pub_point =
      ec_.DecodeFromSpkiDer(epoch_pub_key, context.get());
  if (!epoch_pub_point) {
    LOG(ERROR) << "Failed to convert epoch_pub_key SecureBlob to EC_POINT";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocRecoveryCryptoBadEpochKeyInDecryptResponse),
        ErrorActionSet(
            {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kFatal}),
        CryptoError::CE_OTHER_CRYPTO);
  }
  // Performs scalar multiplication of epoch_pub_point and channel_priv_key.
  // Here we don't use key_auth_value generated from GenerateKeyAuthValue()
  // because key_auth_value is unavailable and will only be recovered from the
  // decrypted response afterward
  hwsec::GenerateDhSharedSecretRequest backend_request_destination_share{
      .ec = ec_,
      .encrypted_own_priv_key =
          brillo::Blob(request.encrypted_channel_priv_key.begin(),
                       request.encrypted_channel_priv_key.end()),
      .extended_pcr_bound_own_priv_key = brillo::Blob(),
      .auth_value = std::nullopt,
      .current_user = *request.obfuscated_username,
      .others_pub_point = std::move(epoch_pub_point),
  };
  hwsec::StatusOr<crypto::ScopedEC_POINT> shared_secret_point =
      hwsec_backend_->GenerateDiffieHellmanSharedSecret(
          std::move(backend_request_destination_share));
  if (!shared_secret_point.ok()) {
    LOG(ERROR) << "Failed to compute shared point from epoch_pub_point and "
                  "channel_priv_key: "
               << shared_secret_point.status();
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocRecoveryCryptoDHFailedInDecryptResponse),
        ErrorActionSet(
            {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kFatal}),
        CryptoError::CE_OTHER_CRYPTO);
  }
  brillo::SecureBlob shared_secret_point_blob;
  crypto::ScopedEC_KEY shared_secret_key =
      ec_.PointToEccKey(*shared_secret_point.value());
  if (!ec_.EncodeToSpkiDer(shared_secret_key, &shared_secret_point_blob,
                           context.get())) {
    LOG(ERROR)
        << "Failed to convert shared_secret_point to SubjectPublicKeyInfo";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(
            kLocRecoveryCryptoEncodePointFailedInDecryptResponse),
        ErrorActionSet(
            {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kFatal}),
        CryptoError::CE_OTHER_CRYPTO);
  }
  brillo::SecureBlob aes_gcm_key;
  if (!GenerateEcdhHkdfSymmetricKey(
          ec_, *shared_secret_point.value(), epoch_pub_key,
          GetResponsePayloadPlainTextHkdfInfo(),
          response_ad.response_payload_salt, RecoveryCrypto::kHkdfHash,
          kAesGcm256KeySize, &aes_gcm_key)) {
    LOG(ERROR) << "Failed to generate ECDH+HKDF recipient key for response "
                  "plain text decryption";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocRecoveryCryptoECDHFailedInDecryptResponse),
        ErrorActionSet(
            {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kFatal}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  // Dispose shared_secret_point after used.
  shared_secret_point.value().reset();
  shared_secret_point_blob.clear();

  brillo::SecureBlob response_plain_text_cbor;
  if (!AesGcmDecrypt(recovery_response.cipher_text,
                     recovery_response.associated_data, recovery_response.tag,
                     aes_gcm_key, recovery_response.iv,
                     &response_plain_text_cbor)) {
    LOG(ERROR) << "Failed to perform AES-GCM decryption of response plain text";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocRecoveryCryptoAESFailedInDecryptResponse),
        ErrorActionSet(
            {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kFatal}),
        CryptoError::CE_OTHER_CRYPTO);
  }
  if (!DeserializeHsmResponsePlainTextFromCbor(response_plain_text_cbor,
                                               response_plain_text)) {
    LOG(ERROR) << "Failed to deserialize Response plain text";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocRecoveryCryptoBadPlainTextInDecryptResponse),
        ErrorActionSet(
            {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kFatal}),
        CryptoError::CE_RECOVERY_FATAL);
  }
  return OkStatus<CryptohomeCryptoError>();
}

bool RecoveryCryptoImpl::GenerateHsmAssociatedData(
    const brillo::SecureBlob& channel_pub_key,
    const brillo::SecureBlob& rsa_pub_key,
    const crypto::ScopedEC_KEY& publisher_key_pair,
    const OnboardingMetadata& onboarding_metadata,
    brillo::SecureBlob* hsm_associated_data) const {
  ScopedBN_CTX context = CreateBigNumContext();
  if (!context.get()) {
    LOG(ERROR) << "Failed to allocate BN_CTX structure";
    return false;
  }

  // Construct associated data for HSM payload: AD = CBOR({publisher_pub_key,
  // channel_pub_key, rsa_pub_key, onboarding_metadata}).
  brillo::SecureBlob publisher_pub_key;
  if (!ec_.EncodeToSpkiDer(publisher_key_pair, &publisher_pub_key,
                           context.get())) {
    LOG(ERROR) << "Failed to convert publisher_pub_key to SubjectPublicKeyInfo";
    return false;
  }

  HsmAssociatedData hsm_ad;
  hsm_ad.publisher_pub_key = publisher_pub_key;
  hsm_ad.channel_pub_key = channel_pub_key;
  hsm_ad.rsa_public_key = rsa_pub_key;
  hsm_ad.onboarding_meta_data = onboarding_metadata;
  if (!SerializeHsmAssociatedDataToCbor(hsm_ad, hsm_associated_data)) {
    LOG(ERROR) << "Failed to generate HSM associated data cbor";
    return false;
  }
  return true;
}

void RecoveryCryptoImpl::GenerateOnboardingMetadata(
    const std::string& gaia_id,
    const std::string& device_user_id,
    const std::string& recovery_id,
    OnboardingMetadata* onboarding_metadata) const {
  onboarding_metadata->cryptohome_user_type = UserType::kGaiaId;
  // The user is uniquely identified by the obfuscated GAIA ID.
  onboarding_metadata->cryptohome_user = gaia_id;
  // Device ID is a stable cryptohome identifier (for cryptohome lifetime only).
  // it does not uniquely identify the user though and gets regenerated on every
  // new device account creation/device powerwash etc.
  onboarding_metadata->device_user_id = device_user_id;
  // The device board name and form-factor.
  onboarding_metadata->board_name = base::SysInfo::GetLsbReleaseBoard();
  std::string device_type;
  if (!base::SysInfo::GetLsbReleaseValue("DEVICETYPE", &device_type)) {
    LOG(ERROR) << "Unable to get device type for recovery onboarding";
    onboarding_metadata->form_factor = kDeviceUnknown;
  } else {
    onboarding_metadata->form_factor = device_type;
  }
  onboarding_metadata->rlz_code = GetRlzCode();
  onboarding_metadata->recovery_id = recovery_id;
}

std::string RecoveryCryptoImpl::LoadStoredRecoveryIdFromFile(
    const base::FilePath& recovery_id_path) const {
  if (recovery_id_path.empty()) {
    LOG(ERROR) << "Unable to get path to serialized RecoveryId container";
    return "";
  }
  CryptoRecoveryIdContainer recovery_id_pb;
  if (!LoadPersistedRecoveryIdContainer(recovery_id_path, &recovery_id_pb)) {
    LOG(ERROR) << "Unable to deserialize RecoveryId protobuf";
    return "";
  }
  if (!recovery_id_pb.has_recovery_id() ||
      recovery_id_pb.recovery_id().empty()) {
    LOG(ERROR) << "Serialized protobuf does not contain the actual RecoveryId";
    return "";
  }
  return hwsec_foundation::SecureBlobToHex(
      brillo::SecureBlob(recovery_id_pb.recovery_id().begin(),
                         recovery_id_pb.recovery_id().end()));
}

std::string RecoveryCryptoImpl::LoadStoredRecoveryId(
    const AccountIdentifier& account_id) const {
  base::FilePath recovery_id_path = GetRecoveryIdPath(account_id);
  return LoadStoredRecoveryIdFromFile(recovery_id_path);
}

bool RecoveryCryptoImpl::GenerateRecoveryIdToFile(
    const base::FilePath& recovery_id_path) const {
  if (recovery_id_path.empty()) {
    LOG(ERROR) << "Unable to get path to serialized RecoveryId container";
    return false;
  }
  CryptoRecoveryIdContainer recovery_id_pb;
  if (!IsRecoveryIdAvailable(recovery_id_path) ||
      !LoadPersistedRecoveryIdContainer(recovery_id_path, &recovery_id_pb)) {
    // Persisted RecoveryIdContainer cannot be retrieved because it has been not
    // created before or there was an error on storage access attempt so we are
    // clearing it up before trying to generate a fresh one.
    recovery_id_pb.Clear();
  }
  GenerateRecoveryIdProto(&recovery_id_pb);
  if (!PersistRecoveryIdContainer(recovery_id_path, recovery_id_pb)) {
    LOG(ERROR) << "Unable to serialize the new Recovery Id";
    return false;
  }
  return true;
}

bool RecoveryCryptoImpl::GenerateRecoveryId(
    const AccountIdentifier& account_id) const {
  base::FilePath recovery_id_path = GetRecoveryIdPath(account_id);
  return GenerateRecoveryIdToFile(recovery_id_path);
}

void RecoveryCryptoImpl::GenerateRecoveryIdProto(
    CryptoRecoveryIdContainer* recovery_id_pb) const {
  if (!recovery_id_pb->has_seed() || !recovery_id_pb->has_increment() ||
      !RotateRecoveryId(recovery_id_pb)) {
    recovery_id_pb->Clear();
    GenerateInitialRecoveryId(recovery_id_pb);
  }
}

std::vector<std::string> RecoveryCryptoImpl::GetLastRecoveryIdsFromFile(
    const base::FilePath& recovery_id_path, int max_depth) const {
  DCHECK_GE(max_depth, 1);
  std::vector<std::string> recovery_id_list;
  CryptoRecoveryIdContainer recovery_id_pb;
  if (!LoadPersistedRecoveryIdContainer(recovery_id_path, &recovery_id_pb)) {
    LOG(ERROR) << "Unable to load stored recovery_id container.";
    return recovery_id_list;
  }
  if (!recovery_id_pb.has_seed() || !recovery_id_pb.has_increment()) {
    LOG(ERROR) << "Recovery_id container does not contain valid fields.";
    return recovery_id_list;
  }

  int increment = recovery_id_pb.increment();
  brillo::SecureBlob recovery_id_seed = brillo::SecureBlob(
      recovery_id_pb.seed().begin(), recovery_id_pb.seed().end());
  for (int counter = 1; counter <= max_depth && increment - counter >= 0;
       counter++) {
    crypto::ScopedBIGNUM seed_bn =
        hwsec_foundation::SecureBlobToBigNum(recovery_id_seed);
    if (BN_add_word(seed_bn.get(), increment - counter) < 0) {
      LOG(ERROR) << "Unable to increment the recovery_id's seed.";
      return recovery_id_list;
    }

    brillo::SecureBlob recovery_id_blob;
    if (!hwsec_foundation::BigNumToSecureBlob(*seed_bn, kRecoveryIdSeedLength,
                                              &recovery_id_blob)) {
      LOG(ERROR) << "Recovery_id cannot be converted to a valid blob.";
      return recovery_id_list;
    }
    recovery_id_blob = hwsec_foundation::Sha256(recovery_id_blob);
    recovery_id_list.push_back(
        hwsec_foundation::SecureBlobToHex(recovery_id_blob));
  }
  return recovery_id_list;
}

std::vector<std::string> RecoveryCryptoImpl::GetLastRecoveryIds(
    const AccountIdentifier& account_id, int max_depth) const {
  return GetLastRecoveryIdsFromFile(GetRecoveryIdPath(account_id), max_depth);
}

bool RecoveryCryptoImpl::RotateRecoveryId(
    CryptoRecoveryIdContainer* recovery_id_pb) const {
  if (!recovery_id_pb->has_seed()) {
    return false;
  }
  crypto::ScopedBIGNUM seed_bn =
      hwsec_foundation::SecureBlobToBigNum(brillo::SecureBlob(
          recovery_id_pb->seed().begin(), recovery_id_pb->seed().end()));
  if (!recovery_id_pb->has_increment()) {
    return false;
  }
  int increment = recovery_id_pb->increment();

  if (BN_add_word(seed_bn.get(), increment) < 0) {
    LOG(ERROR) << "Unable to increment the Recovery Id's seed";
    return false;
  }
  brillo::SecureBlob recovery_id_blob;
  if (!hwsec_foundation::BigNumToSecureBlob(*seed_bn, kRecoveryIdSeedLength,
                                            &recovery_id_blob)) {
    LOG(ERROR) << "Unable to convert Recovery Id to a binary blob";
    return false;
  }
  // Computes a new recovery_id by hashing seed+increment. The hash
  // (in the current version Sha256) must be resistant against length
  // extension attacks.
  recovery_id_blob = hwsec_foundation::Sha256(recovery_id_blob);
  recovery_id_pb->set_increment(increment + 1);
  recovery_id_pb->set_recovery_id(recovery_id_blob.data(),
                                  recovery_id_blob.size());
  return true;
}

void RecoveryCryptoImpl::GenerateInitialRecoveryId(
    CryptoRecoveryIdContainer* recovery_id_pb) const {
  brillo::SecureBlob seed_blob =
      hwsec_foundation::CreateSecureRandomBlob(kRecoveryIdSeedLength);
  brillo::SecureBlob recovery_id_blob = hwsec_foundation::Sha256(seed_blob);
  recovery_id_pb->set_seed(seed_blob.data(), seed_blob.size());
  recovery_id_pb->set_increment(1);
  recovery_id_pb->set_recovery_id(recovery_id_blob.data(),
                                  recovery_id_blob.size());
}

// Checks if the serialized RecoveryId was already generated and stored in user
// home directory. It returns false if we cannot access user home directory
// (but if so we should not try to construct OnboardingMetadata and other
// recovery data blobs) of have not explicitly generated the RecoveryId yet.
bool RecoveryCryptoImpl::IsRecoveryIdAvailable(
    const base::FilePath& recovery_id_path) const {
  return platform_->FileExists(recovery_id_path);
}

bool RecoveryCryptoImpl::LoadPersistedRecoveryIdContainer(
    const base::FilePath& recovery_id_path,
    CryptoRecoveryIdContainer* recovery_id_pb) const {
  if (!IsRecoveryIdAvailable(recovery_id_path)) {
    return false;
  }
  std::string recovery_id_serialized_pb;
  if (!platform_->ReadFileToString(recovery_id_path,
                                   &recovery_id_serialized_pb)) {
    LOG(ERROR) << "Error reading serialized RecoveryId protobuf";
    return false;
  }
  if (!recovery_id_pb->ParseFromString(recovery_id_serialized_pb)) {
    LOG(ERROR) << "Unable to parse RecoveryId protobuf";
    return false;
  }
  return true;
}

bool RecoveryCryptoImpl::PersistRecoveryIdContainer(
    const base::FilePath& recovery_id_path,
    const CryptoRecoveryIdContainer& recovery_id_pb) const {
  std::string recovery_id_serialized_pb;
  if (!recovery_id_pb.SerializeToString(&recovery_id_serialized_pb)) {
    return false;
  }
  if (!platform_->WriteStringToFileAtomicDurable(
          recovery_id_path, recovery_id_serialized_pb, kKeyFilePermissions)) {
    LOG(ERROR) << "Failed to write serialized RecoveryId: "
               << recovery_id_path.value();
    return false;
  }
  return true;
}

}  // namespace cryptorecovery
}  // namespace cryptohome
