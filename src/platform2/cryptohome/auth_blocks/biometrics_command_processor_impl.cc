// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/biometrics_command_processor_impl.h"

#include <memory>
#include <optional>
#include <utility>

#include <base/functional/callback.h>
#include <biod/biod_proxy/auth_stack_manager_proxy_base.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/secure_blob.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <libhwsec-foundation/crypto/aes.h>
#include <libhwsec-foundation/crypto/big_num_util.h>
#include <libhwsec-foundation/crypto/ecdh_hkdf.h>
#include <libhwsec-foundation/crypto/sha.h>

#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/error/locations.h"

namespace cryptohome {

namespace {

using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::CryptohomeError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec_foundation::EllipticCurve;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;

// We guarantee the returned ScopedEC_KEY is non-null. If it's null, we'll
// return an error instead.
CryptohomeStatusOr<crypto::ScopedEC_KEY> GenerateEcKey() {
  hwsec_foundation::ScopedBN_CTX context =
      hwsec_foundation::CreateBigNumContext();
  std::optional<EllipticCurve> ec =
      EllipticCurve::Create(EllipticCurve::CurveType::kPrime256, context.get());
  if (!ec.has_value()) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsProcessorCreateEcFailedInGenKey),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }
  crypto::ScopedEC_KEY key = ec->GenerateKey(context.get());
  if (!key) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsProcessorNullCreatedKeyInGenKey),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }
  return key;
}

CryptohomeStatusOr<biod::FpPublicKey> GetFpPublicKeyFromEcKey(
    const EC_KEY& key) {
  const EC_POINT* pub_point = EC_KEY_get0_public_key(&key);
  hwsec_foundation::ScopedBN_CTX context =
      hwsec_foundation::CreateBigNumContext();
  std::optional<EllipticCurve> ec =
      EllipticCurve::Create(EllipticCurve::CurveType::kPrime256, context.get());
  if (!ec.has_value()) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsProcessorCreateEcFailedInGetKey),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  crypto::ScopedBIGNUM out_x = hwsec_foundation::CreateBigNum(),
                       out_y = hwsec_foundation::CreateBigNum();
  if (!out_x || !out_y) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsProcessorCreateBigNumsFailedInGetKey),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }
  if (!EC_POINT_get_affine_coordinates(ec->GetGroup(), pub_point, out_x.get(),
                                       out_y.get(), context.get())) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsProcessorGetCoordsFailedInGetKey),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }
  brillo::SecureBlob out_x_blob, out_y_blob;
  if (!hwsec_foundation::BigNumToSecureBlob(*out_x, 32, &out_x_blob) ||
      !hwsec_foundation::BigNumToSecureBlob(*out_y, 32, &out_y_blob)) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsProcessorPointToBlobFailedInGetKey),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  biod::FpPublicKey fp_pub_key;
  fp_pub_key.set_x(out_x_blob.to_string());
  fp_pub_key.set_y(out_y_blob.to_string());

  return fp_pub_key;
}

// We guarantee the returned ScopedEC_POINT is non-null. If it's null, we'll
// return an error instead.
CryptohomeStatusOr<crypto::ScopedEC_POINT> GetEcPointFromFpPublicKey(
    const biod::FpPublicKey& key) {
  hwsec_foundation::ScopedBN_CTX context =
      hwsec_foundation::CreateBigNumContext();
  std::optional<EllipticCurve> ec =
      EllipticCurve::Create(EllipticCurve::CurveType::kPrime256, context.get());
  if (!ec.has_value()) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsProcessorCreateEcFailedInGetPoint),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  crypto::ScopedEC_POINT point = ec->CreatePoint();
  if (!point) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsProcessorNullCreatedPointInGetPoint),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }
  const brillo::SecureBlob in_x_blob(brillo::BlobFromString(key.x())),
      in_y_blob(brillo::BlobFromString(key.y()));
  const crypto::ScopedBIGNUM in_x =
      hwsec_foundation::SecureBlobToBigNum(in_x_blob);
  const crypto::ScopedBIGNUM in_y =
      hwsec_foundation::SecureBlobToBigNum(in_y_blob);
  if (!in_x || !in_y) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsProcessorKeyToBigNumFailedInGetPoint),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }
  if (!EC_POINT_set_affine_coordinates(ec->GetGroup(), point.get(), in_x.get(),
                                       in_y.get(), context.get())) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsProcessorSetCoordsFailedInGetPoint),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }
  return point;
}

CryptohomeStatusOr<brillo::SecureBlob> DecryptSecret(
    const brillo::Blob& encrypted_secret,
    const brillo::Blob& iv,
    const EC_POINT& others_pub_point,
    const EC_KEY& own_priv_key) {
  hwsec_foundation::ScopedBN_CTX context =
      hwsec_foundation::CreateBigNumContext();
  std::optional<EllipticCurve> ec =
      EllipticCurve::Create(EllipticCurve::CurveType::kPrime256, context.get());
  if (!ec.has_value()) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(
            kLocBiometricsProcessorCreateEcFailedInDecryptSecret),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  crypto::ScopedEC_POINT shared_point =
      hwsec_foundation::ComputeEcdhSharedSecretPoint(
          *ec, others_pub_point, *EC_KEY_get0_private_key(&own_priv_key));
  if (!shared_point) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(
            kLocBiometricsProcessorComputeSharedPointFailedInDecryptSecret),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  brillo::SecureBlob shared_secret;
  if (!hwsec_foundation::ComputeEcdhSharedSecret(*ec, *shared_point,
                                                 &shared_secret)) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(
            kLocBiometricsProcessorComputeSharedSecretFailedInDecryptSecret),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  // The key encrypting the secret is derived by SHA256 hashing the shared
  // secret.
  brillo::SecureBlob aes_key = hwsec_foundation::Sha256(shared_secret);
  brillo::SecureBlob secret;
  if (!hwsec_foundation::AesDecryptSpecifyBlockMode(
          brillo::SecureBlob(encrypted_secret), 0, encrypted_secret.size(),
          aes_key, brillo::SecureBlob(iv),
          hwsec_foundation::PaddingScheme::kPaddingNone,
          hwsec_foundation::BlockMode::kCtr, &secret)) {
    LOG(ERROR) << "Failed to decrypt encrypted_secret.";
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsProcessorDecryptFailedInDecryptSecret),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  return secret;
}

CryptohomeStatus DeriveAuthSecrets(const biod::FpPublicKey& pub,
                                   const std::string& encrypted_secret,
                                   const std::string& iv,
                                   const EC_KEY& key,
                                   brillo::SecureBlob& auth_secret,
                                   brillo::SecureBlob& auth_pin) {
  CryptohomeStatusOr<crypto::ScopedEC_POINT> pub_point =
      GetEcPointFromFpPublicKey(pub);
  if (!pub_point.ok()) {
    return MakeStatus<CryptohomeError>(
               CRYPTOHOME_ERR_LOC(
                   kLocBiometricsProcessorParseKeyFailedInDerive))
        .Wrap(std::move(pub_point).err_status());
  }
  CryptohomeStatusOr<brillo::SecureBlob> secret =
      DecryptSecret(brillo::BlobFromString(encrypted_secret),
                    brillo::BlobFromString(iv), **pub_point, key);
  if (!secret.ok()) {
    return MakeStatus<CryptohomeError>(
               CRYPTOHOME_ERR_LOC(
                   kLocBiometricsProcessorDecryptSecretFailedInDerive))
        .Wrap(std::move(secret).err_status());
  }
  auth_secret = std::move(*secret);
  // AuthPin can be any value that is derivable from AuthSecret, but not vice
  // versa. We derive AuthPin by SHA256-hashing AuthSecret.
  auth_pin = hwsec_foundation::Sha256(auth_secret);
  return OkStatus<CryptohomeError>();
}

CryptohomeStatus CreateCredentialStatusToCryptohomeStatus(
    biod::CreateCredentialReply::CreateCredentialStatus biod_status) {
  switch (biod_status) {
    case biod::CreateCredentialReply::SUCCESS:
      return OkStatus<CryptohomeError>();
    case biod::CreateCredentialReply::INCORRECT_STATE:
      return MakeStatus<CryptohomeError>(
          CRYPTOHOME_ERR_LOC(
              kLocBiometricsProcessorCreateCredentialWrongSession),
          ErrorActionSet({PossibleAction::kRetry, PossibleAction::kReboot}),
          user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL);
    // Error codes other than INCORRECT_STATE shouldn't usually happen.
    default:
      return MakeStatus<CryptohomeError>(
          CRYPTOHOME_ERR_LOC(
              kLocBiometricsProcessorCreateCredentialBiodInternalError),
          ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                          PossibleAction::kReboot}),
          user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL);
  }
}

CryptohomeStatus AuthenticateCredentialStatusToCryptohomeStatus(
    biod::AuthenticateCredentialReply::AuthenticateCredentialStatus
        biod_status) {
  switch (biod_status) {
    case biod::AuthenticateCredentialReply::SUCCESS:
      return OkStatus<CryptohomeError>();
    case biod::AuthenticateCredentialReply::INCORRECT_STATE:
      return MakeStatus<CryptohomeError>(
          CRYPTOHOME_ERR_LOC(
              kLocBiometricsProcessorMatchCredentialWrongSession),
          ErrorActionSet({PossibleAction::kRetry, PossibleAction::kReboot}),
          user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL);
    case biod::AuthenticateCredentialReply::NO_TEMPLATES:
      return MakeStatus<CryptohomeError>(
          CRYPTOHOME_ERR_LOC(kLocBiometricsProcessorMatchCredentialNoRecords),
          ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
          user_data_auth::CRYPTOHOME_ERROR_KEY_NOT_FOUND);
    // Other error codes shouldn't usually happen.
    default:
      return MakeStatus<CryptohomeError>(
          CRYPTOHOME_ERR_LOC(
              kLocBiometricsProcessorMatchCredentialBiodInternalError),
          ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                          PossibleAction::kReboot}),
          user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL);
  }
}

CryptohomeStatus ScanResultToCryptohomeStatus(biod::ScanResult scan_result) {
  switch (scan_result) {
    case biod::ScanResult::SCAN_RESULT_SUCCESS:
      return OkStatus<CryptohomeError>();
    // TODO(b/268597445): Include more fine-grained match error types in the
    // returned error.
    case biod::SCAN_RESULT_PARTIAL:
    case biod::SCAN_RESULT_INSUFFICIENT:
    case biod::SCAN_RESULT_SENSOR_DIRTY:
    case biod::SCAN_RESULT_TOO_SLOW:
    case biod::SCAN_RESULT_TOO_FAST:
    case biod::SCAN_RESULT_IMMOBILE:
    case biod::SCAN_RESULT_NO_MATCH:
      return MakeStatus<CryptohomeError>(
          CRYPTOHOME_ERR_LOC(kLocBiometricsProcessorMatchCredentialNoMatch),
          ErrorActionSet(PrimaryAction::kIncorrectAuth),
          user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_RETRY_REQUIRED);
    default:
      return MakeStatus<CryptohomeError>(
          CRYPTOHOME_ERR_LOC(
              kLocBiometricsProcessorMatchCredentialUnexpectedScanResult),
          ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
          user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_RETRY_REQUIRED);
  }
}

user_data_auth::FingerprintScanResult ScanResultToFingerprintResult(
    biod::ScanResult result) {
  switch (result) {
    case biod::SCAN_RESULT_SUCCESS:
      return user_data_auth::FINGERPRINT_SCAN_RESULT_SUCCESS;
    case biod::SCAN_RESULT_PARTIAL:
      return user_data_auth::FINGERPRINT_SCAN_RESULT_PARTIAL;
    case biod::SCAN_RESULT_INSUFFICIENT:
      return user_data_auth::FINGERPRINT_SCAN_RESULT_INSUFFICIENT;
    case biod::SCAN_RESULT_SENSOR_DIRTY:
      return user_data_auth::FINGERPRINT_SCAN_RESULT_SENSOR_DIRTY;
    case biod::SCAN_RESULT_TOO_SLOW:
      return user_data_auth::FINGERPRINT_SCAN_RESULT_TOO_SLOW;
    case biod::SCAN_RESULT_TOO_FAST:
      return user_data_auth::FINGERPRINT_SCAN_RESULT_TOO_FAST;
    case biod::SCAN_RESULT_IMMOBILE:
      return user_data_auth::FINGERPRINT_SCAN_RESULT_IMMOBILE;
    default:
      return user_data_auth::FINGERPRINT_SCAN_RESULT_ENROLL_OTHER;
  }
}

}  // namespace

BiometricsCommandProcessorImpl::BiometricsCommandProcessorImpl(
    std::unique_ptr<biod::AuthStackManagerProxyBase> proxy)
    : on_enroll_scan_done_(base::DoNothing()),
      on_auth_scan_done_(base::DoNothing()),
      on_session_failed_(base::DoNothing()),
      proxy_(std::move(proxy)) {
  pending_signal_connections_ = 3;
  proxy_->ConnectToEnrollScanDoneSignal(
      base::BindRepeating(&BiometricsCommandProcessorImpl::OnEnrollScanDone,
                          base::Unretained(this)),
      base::BindOnce(&BiometricsCommandProcessorImpl::OnSignalConnected,
                     base::Unretained(this)));
  proxy_->ConnectToAuthScanDoneSignal(
      base::BindRepeating(&BiometricsCommandProcessorImpl::OnAuthScanDone,
                          base::Unretained(this)),
      base::BindOnce(&BiometricsCommandProcessorImpl::OnSignalConnected,
                     base::Unretained(this)));
  proxy_->ConnectToSessionFailedSignal(
      base::BindRepeating(&BiometricsCommandProcessorImpl::OnSessionFailed,
                          base::Unretained(this)),
      base::BindOnce(&BiometricsCommandProcessorImpl::OnSignalConnected,
                     base::Unretained(this)));
}

bool BiometricsCommandProcessorImpl::IsReady() {
  return pending_signal_connections_ == 0;
}

void BiometricsCommandProcessorImpl::SetEnrollScanDoneCallback(
    base::RepeatingCallback<void(user_data_auth::AuthEnrollmentProgress,
                                 std::optional<brillo::Blob>)> on_done) {
  on_enroll_scan_done_ = on_done;
}

void BiometricsCommandProcessorImpl::SetAuthScanDoneCallback(
    base::RepeatingCallback<void(user_data_auth::AuthScanDone, brillo::Blob)>
        on_done) {
  on_auth_scan_done_ = on_done;
}

void BiometricsCommandProcessorImpl::SetSessionFailedCallback(
    base::RepeatingCallback<void()> on_failure) {
  on_session_failed_ = on_failure;
}

void BiometricsCommandProcessorImpl::StartEnrollSession(
    base::OnceCallback<void(bool)> on_done) {
  proxy_->StartEnrollSession(std::move(on_done));
}

void BiometricsCommandProcessorImpl::StartAuthenticateSession(
    ObfuscatedUsername obfuscated_username,
    base::OnceCallback<void(bool)> on_done) {
  proxy_->StartAuthSession(std::move(*obfuscated_username), std::move(on_done));
}

void BiometricsCommandProcessorImpl::CreateCredential(
    ObfuscatedUsername obfuscated_username,
    OperationInput payload,
    OperationCallback on_done) {
  CryptohomeStatusOr<crypto::ScopedEC_KEY> key = GenerateEcKey();
  if (!key.ok()) {
    std::move(on_done).Run(
        MakeStatus<CryptohomeError>(
            CRYPTOHOME_ERR_LOC(
                kLocBiometricsProcessorCreateCredentialKeygenFailed))
            .Wrap(std::move(key).err_status()));
    return;
  }
  CryptohomeStatusOr<biod::FpPublicKey> pub = GetFpPublicKeyFromEcKey(**key);
  if (!pub.ok()) {
    std::move(on_done).Run(
        MakeStatus<CryptohomeError>(
            CRYPTOHOME_ERR_LOC(
                kLocBiometricsProcessorCreateCredentialGetKeyFailed))
            .Wrap(std::move(pub).err_status()));
    return;
  }

  biod::CreateCredentialRequest request;
  request.set_user_id(std::move(*obfuscated_username));
  request.set_gsc_nonce(brillo::BlobToString(payload.nonce));
  request.set_encrypted_label_seed(
      brillo::BlobToString(payload.encrypted_label_seed));
  request.set_iv(brillo::BlobToString(payload.iv));
  *request.mutable_pub() = std::move(*pub);

  proxy_->CreateCredential(
      request,
      base::BindOnce(&BiometricsCommandProcessorImpl::OnCreateCredentialReply,
                     base::Unretained(this), std::move(on_done),
                     std::move(*key)));
}

void BiometricsCommandProcessorImpl::MatchCredential(
    OperationInput payload, OperationCallback on_done) {
  CryptohomeStatusOr<crypto::ScopedEC_KEY> key = GenerateEcKey();
  if (!key.ok()) {
    std::move(on_done).Run(
        MakeStatus<CryptohomeError>(
            CRYPTOHOME_ERR_LOC(
                kLocBiometricsProcessorMatchCredentialKeygenFailed))
            .Wrap(std::move(key).err_status()));
    return;
  }
  CryptohomeStatusOr<biod::FpPublicKey> pub = GetFpPublicKeyFromEcKey(**key);
  if (!pub.ok()) {
    std::move(on_done).Run(
        MakeStatus<CryptohomeError>(
            CRYPTOHOME_ERR_LOC(
                kLocBiometricsProcessorMatchCredentialGetKeyFailed))
            .Wrap(std::move(pub).err_status()));
    return;
  }

  biod::AuthenticateCredentialRequest request;
  request.set_gsc_nonce(brillo::BlobToString(payload.nonce));
  request.set_encrypted_label_seed(
      brillo::BlobToString(payload.encrypted_label_seed));
  request.set_iv(brillo::BlobToString(payload.iv));
  *request.mutable_pub() = std::move(*pub);

  proxy_->AuthenticateCredential(
      request,
      base::BindOnce(
          &BiometricsCommandProcessorImpl::OnAuthenticateCredentialReply,
          base::Unretained(this), std::move(on_done), std::move(*key)));
}

void BiometricsCommandProcessorImpl::EndEnrollSession() {
  proxy_->EndEnrollSession();
}

void BiometricsCommandProcessorImpl::EndAuthenticateSession() {
  proxy_->EndAuthSession();
}

void BiometricsCommandProcessorImpl::OnSignalConnected(
    const std::string& interface, const std::string& signal, bool success) {
  if (!success) {
    // Fail silently because biometrics isn't available on every device.
    VLOG(1) << "Failed to connect to signal " << signal << " on interface "
            << interface << ".";
    return;
  }
  pending_signal_connections_--;
}

void BiometricsCommandProcessorImpl::OnEnrollScanDone(dbus::Signal* signal) {
  dbus::MessageReader signal_reader(signal);
  biod::EnrollScanDone message;
  if (!signal_reader.PopArrayOfBytesAsProto(&message)) {
    return;
  }
  user_data_auth::AuthEnrollmentProgress progress;
  progress.mutable_scan_result()->set_fingerprint_result(
      ScanResultToFingerprintResult(message.scan_result()));
  progress.set_done(message.done());
  progress.mutable_fingerprint_progress()->set_percent_complete(
      message.percent_complete());

  std::optional<brillo::Blob> nonce = std::nullopt;
  if (message.done()) {
    nonce = brillo::BlobFromString(message.auth_nonce());
  }
  on_enroll_scan_done_.Run(std::move(progress), std::move(nonce));
}

void BiometricsCommandProcessorImpl::OnAuthScanDone(dbus::Signal* signal) {
  dbus::MessageReader signal_reader(signal);
  biod::AuthScanDone message;
  if (!signal_reader.PopArrayOfBytesAsProto(&message)) {
    return;
  }
  user_data_auth::AuthScanDone scan_done;
  scan_done.mutable_scan_result()->set_fingerprint_result(
      user_data_auth::FINGERPRINT_SCAN_RESULT_SUCCESS);
  on_auth_scan_done_.Run(std::move(scan_done),
                         brillo::BlobFromString(message.auth_nonce()));
}

void BiometricsCommandProcessorImpl::OnSessionFailed(dbus::Signal* signal) {
  LOG(WARNING) << "Biometrics session failure.";
  on_session_failed_.Run();
}

void BiometricsCommandProcessorImpl::OnCreateCredentialReply(
    OperationCallback on_done,
    crypto::ScopedEC_KEY key,
    std::optional<biod::CreateCredentialReply> reply) {
  if (!reply.has_value()) {
    std::move(on_done).Run(MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsProcessorCreateCredentialBiodNoResp),
        ErrorActionSet({PossibleAction::kRetry, PossibleAction::kReboot}),
        user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL));
    return;
  }
  CryptohomeStatus status =
      CreateCredentialStatusToCryptohomeStatus(reply->status());
  if (!status.ok()) {
    std::move(on_done).Run(std::move(status).err_status());
    return;
  }

  brillo::SecureBlob auth_secret, auth_pin;
  status = DeriveAuthSecrets(reply->pub(), reply->encrypted_secret(),
                             reply->iv(), *key, auth_secret, auth_pin);
  if (!status.ok()) {
    std::move(on_done).Run(
        MakeStatus<CryptohomeError>(
            CRYPTOHOME_ERR_LOC(
                kLocBiometricsProcessorCreateCredentialDeriveSecretsFailed))
            .Wrap(std::move(status)));
    return;
  }

  std::move(on_done).Run(OperationOutput{.record_id = reply->record_id(),
                                         .auth_secret = std::move(auth_secret),
                                         .auth_pin = std::move(auth_pin)});
}

void BiometricsCommandProcessorImpl::OnAuthenticateCredentialReply(
    OperationCallback on_done,
    crypto::ScopedEC_KEY key,
    std::optional<biod::AuthenticateCredentialReply> reply) {
  if (!reply.has_value()) {
    std::move(on_done).Run(MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsProcessorMatchCredentialBiodNoResp),
        ErrorActionSet({PossibleAction::kRetry, PossibleAction::kReboot}),
        user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL));
    return;
  }
  CryptohomeStatus status =
      AuthenticateCredentialStatusToCryptohomeStatus(reply->status());
  if (!status.ok()) {
    std::move(on_done).Run(std::move(status).err_status());
    return;
  }
  status = ScanResultToCryptohomeStatus(reply->scan_result());
  if (!status.ok()) {
    std::move(on_done).Run(std::move(status).err_status());
    return;
  }

  brillo::SecureBlob auth_secret, auth_pin;
  status = DeriveAuthSecrets(reply->pub(), reply->encrypted_secret(),
                             reply->iv(), *key, auth_secret, auth_pin);
  if (!status.ok()) {
    std::move(on_done).Run(
        MakeStatus<CryptohomeError>(
            CRYPTOHOME_ERR_LOC(
                kLocBiometricsProcessorMatchCredentialDeriveSecretsFailed))
            .Wrap(std::move(status)));
    return;
  }

  std::move(on_done).Run(OperationOutput{.record_id = reply->record_id(),
                                         .auth_secret = std::move(auth_secret),
                                         .auth_pin = std::move(auth_pin)});
}

}  // namespace cryptohome
