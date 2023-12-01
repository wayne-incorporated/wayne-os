// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/u2f_command_processor_generic.h"

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/strings/string_number_conversions.h>
#include <base/time/time.h>
#include <brillo/secure_blob.h>
#include <chromeos/cbor/values.h>
#include <chromeos/cbor/writer.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <u2f/proto_bindings/u2f_interface.pb.h>
#include <user_data_auth-client/user_data_auth/dbus-proxies.h>

#include "u2fd/client/user_state.h"
#include "u2fd/client/util.h"
#include "u2fd/u2f_command_processor.h"
#include "u2fd/webauthn_handler.h"
#include "u2fd/webauthn_storage.h"

namespace u2f {

namespace {

const int kCurrentVersion = 1;
const int kAuthSaltSize = 16;
const int kHashToSignSize = 32;

// Use a big timeout for cryptohome. See b/172945202.
constexpr base::TimeDelta kCryptohomeTimeout = base::Minutes(2);

// COSE key parameters.
// https://tools.ietf.org/html/rfc8152#section-7.1
const int kCoseKeyKtyLabel = 1;
const int kCoseKeyKtyRsa = 3;
const int kCoseKeyAlgLabel = 3;
const int kCoseKeyAlgRs256 = -257;

// COSE key type parameters.
// https://tools.ietf.org/html/rfc8152#section-13.1.1
const int kCoseRsaKeyNLabel = -1;
const int kCoseRsaKeyELabel = -2;

struct credential_id_v1 {
  int version;
  uint8_t auth_salt[kAuthSaltSize];
  uint8_t hmac[SHA256_DIGEST_LENGTH];
  // for integrity check against corrupted data, instead of malicious attacks.
  uint8_t hash[SHA256_DIGEST_LENGTH];
};

std::vector<uint8_t> EncodeCredentialPublicKeyInCBOR(
    const brillo::Blob& public_exponent, const brillo::Blob& modulus) {
  cbor::Value::MapValue cbor_map;
  cbor_map[cbor::Value(kCoseKeyKtyLabel)] = cbor::Value(kCoseKeyKtyRsa);
  cbor_map[cbor::Value(kCoseKeyAlgLabel)] = cbor::Value(kCoseKeyAlgRs256);
  cbor_map[cbor::Value(kCoseRsaKeyNLabel)] = cbor::Value(modulus);
  cbor_map[cbor::Value(kCoseRsaKeyELabel)] = cbor::Value(public_exponent);
  return *cbor::Writer::Write(cbor::Value(std::move(cbor_map)));
}

bool IsCredentialIdValid(struct credential_id_v1 cred) {
  std::vector<uint8_t> data_to_hash;
  util::AppendToVector(cred.version, &data_to_hash);
  util::AppendToVector(cred.auth_salt, &data_to_hash);
  util::AppendToVector(cred.hmac, &data_to_hash);
  std::vector<uint8_t> hash = util::Sha256(data_to_hash);

  std::vector<uint8_t> original_hash;
  util::AppendToVector(cred.hash, &original_hash);
  return original_hash == hash;
}

// Normally we shouldn't put secure blob data into raw vectors, but in this U2F
// implementation the cred secret is more like a salt than a secret, so it's
// fine to not protect it using secure container.
void AppendCredSecretToVector(const brillo::SecureBlob& from,
                              std::vector<uint8_t>* to) {
  to->insert(to->end(), from.begin(), from.end());
}

}  // namespace

U2fCommandProcessorGeneric::U2fCommandProcessorGeneric(
    UserState* user_state,
    std::unique_ptr<org::chromium::UserDataAuthInterfaceProxyInterface>
        cryptohome_proxy,
    std::unique_ptr<const hwsec::U2fFrontend> u2f_frontend)
    : user_state_(user_state),
      cryptohome_proxy_(std::move(cryptohome_proxy)),
      u2f_frontend_(std::move(u2f_frontend)) {
  CHECK(u2f_frontend_);
}

MakeCredentialResponse::MakeCredentialStatus
U2fCommandProcessorGeneric::U2fGenerate(
    const std::vector<uint8_t>& rp_id_hash,
    const brillo::SecureBlob& credential_secret,
    PresenceRequirement presence_requirement,
    bool uv_compatible,
    const brillo::Blob* auth_time_secret_hash,
    std::vector<uint8_t>* credential_id,
    CredentialPublicKey* credential_public_key,
    std::vector<uint8_t>* credential_key_blob) {
  DCHECK(rp_id_hash.size() == SHA256_DIGEST_LENGTH);

  if (!uv_compatible ||
      presence_requirement == PresenceRequirement::kPowerButton) {
    // On non-GSC devices we don't support user presence auth.
    return MakeCredentialResponse::INVALID_REQUEST;
  }

  if (credential_secret.size() != kCredentialSecretSize) {
    return MakeCredentialResponse::INVALID_REQUEST;
  }

  std::optional<brillo::SecureBlob> webauthn_secret = GetWebAuthnSecret();
  if (!webauthn_secret.has_value()) {
    LOG(ERROR) << "No webauthn secret.";
    return MakeCredentialResponse::INTERNAL_ERROR;
  }

  brillo::Blob auth_salt(kAuthSaltSize);
  if (RAND_bytes(auth_salt.data(), auth_salt.size()) != 1) {
    LOG(ERROR) << "Failed to generate auth salt.";
    return MakeCredentialResponse::INTERNAL_ERROR;
  }

  if (!u2f_frontend_->IsReady().value_or(false)) {
    LOG(WARNING) << "U2F frontend is not ready.";
    return MakeCredentialResponse::INTERNAL_ERROR;
  }

  hwsec::StatusOr<hwsec::U2fFrontend::CreateKeyResult> result =
      u2f_frontend_->GenerateRSASigningKey(*webauthn_secret);
  if (!result.ok()) {
    LOG(ERROR) << "Failed to generate signing key: " << result.status() << ".";
    return MakeCredentialResponse::INTERNAL_ERROR;
  }
  hwsec::StatusOr<hwsec::RSAPublicInfo> pub_info =
      u2f_frontend_->GetRSAPublicKey(result->key.GetKey());
  if (!pub_info.ok()) {
    LOG(ERROR) << "Failed to get RSA public key: " << pub_info.status() << ".";
    return MakeCredentialResponse::INTERNAL_ERROR;
  }
  if (credential_key_blob) {
    *credential_key_blob = result->key_blob;
  }
  credential_public_key->cbor =
      EncodeCredentialPublicKeyInCBOR(pub_info->exponent, pub_info->modulus);

  std::vector<uint8_t> data;

  util::AppendToVector(kCurrentVersion, &data);
  util::AppendToVector(auth_salt, &data);
  util::AppendToVector(rp_id_hash, &data);
  AppendCredSecretToVector(credential_secret, &data);
  util::AppendToVector(result->key_blob, &data);

  std::vector<uint8_t> hmac = util::HmacSha256(*webauthn_secret, data);

  std::vector<uint8_t> data_to_hash;
  util::AppendToVector(kCurrentVersion, &data_to_hash);
  util::AppendToVector(auth_salt, &data_to_hash);
  util::AppendToVector(hmac, &data_to_hash);
  std::vector<uint8_t> hash = util::Sha256(data_to_hash);

  struct credential_id_v1 cred;
  memset(&cred, 0, sizeof(cred));
  cred.version = kCurrentVersion;
  util::VectorToObject(auth_salt, cred.auth_salt, kAuthSaltSize);
  util::VectorToObject(hmac, cred.hmac, SHA256_DIGEST_LENGTH);
  util::VectorToObject(hash, cred.hash, SHA256_DIGEST_LENGTH);

  credential_id->clear();
  util::AppendToVector(cred, credential_id);

  return MakeCredentialResponse::SUCCESS;
}

GetAssertionResponse::GetAssertionStatus U2fCommandProcessorGeneric::U2fSign(
    const std::vector<uint8_t>& rp_id_hash,
    const std::vector<uint8_t>& hash_to_sign,
    const std::vector<uint8_t>& credential_id,
    const brillo::SecureBlob& credential_secret,
    const std::vector<uint8_t>* credential_key_blob,
    PresenceRequirement presence_requirement,
    std::vector<uint8_t>* signature) {
  DCHECK(rp_id_hash.size() == SHA256_DIGEST_LENGTH);

  if (presence_requirement == PresenceRequirement::kPowerButton) {
    return GetAssertionResponse::INVALID_REQUEST;
  }

  if (hash_to_sign.size() != kHashToSignSize ||
      credential_secret.size() != kCredentialSecretSize ||
      !credential_key_blob) {
    return GetAssertionResponse::INVALID_REQUEST;
  }

  struct credential_id_v1 cred;
  if (!util::VectorToObject(credential_id, &cred, sizeof(cred)) ||
      cred.version != kCurrentVersion) {
    return GetAssertionResponse::INVALID_REQUEST;
  }

  if (!IsCredentialIdValid(cred)) {
    LOG(ERROR) << "Hash verification failed.";
    return GetAssertionResponse::INVALID_REQUEST;
  }

  std::optional<brillo::SecureBlob> webauthn_secret = GetWebAuthnSecret();
  if (!webauthn_secret.has_value()) {
    LOG(ERROR) << "No webauthn secret.";
    return GetAssertionResponse::INTERNAL_ERROR;
  }

  // hmac verification
  std::vector<uint8_t> data;

  // Append the version number.
  util::AppendToVector(cred.version, &data);
  util::AppendToVector(cred.auth_salt, &data);
  util::AppendToVector(rp_id_hash, &data);
  AppendCredSecretToVector(credential_secret, &data);
  util::AppendToVector(*credential_key_blob, &data);

  std::vector<uint8_t> hmac = util::HmacSha256(*webauthn_secret, data);

  std::vector<uint8_t> original_hmac;
  util::AppendToVector(cred.hmac, &original_hmac);

  if (hmac != original_hmac) {
    LOG(ERROR) << "Hmac verification failed.";
    return GetAssertionResponse::INTERNAL_ERROR;
  }

  if (!u2f_frontend_->IsReady().value_or(false)) {
    LOG(WARNING) << "U2F frontend is not ready.";
    return GetAssertionResponse::INTERNAL_ERROR;
  }

  hwsec::StatusOr<hwsec::ScopedKey> key =
      u2f_frontend_->LoadKey(*credential_key_blob, *webauthn_secret);
  if (!key.ok()) {
    LOG(ERROR) << "Failed to load signing key: " << key.status() << ".";
    return GetAssertionResponse::INTERNAL_ERROR;
  }
  hwsec::StatusOr<std::vector<uint8_t>> sig =
      u2f_frontend_->RSASign(key->GetKey(), hash_to_sign);
  if (!sig.ok()) {
    LOG(ERROR) << "Failed to generate signature: " << sig.status() << ".";
    return GetAssertionResponse::INTERNAL_ERROR;
  }
  *signature = std::move(*sig);

  return GetAssertionResponse::SUCCESS;
}

HasCredentialsResponse::HasCredentialsStatus
U2fCommandProcessorGeneric::U2fSignCheckOnly(
    const std::vector<uint8_t>& rp_id_hash,
    const std::vector<uint8_t>& credential_id,
    const brillo::SecureBlob& credential_secret,
    const std::vector<uint8_t>* credential_key_blob) {
  if (rp_id_hash.size() != SHA256_DIGEST_LENGTH ||
      credential_secret.size() != kCredentialSecretSize ||
      !credential_key_blob) {
    return HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID;
  }

  struct credential_id_v1 cred;
  if (!util::VectorToObject(credential_id, &cred, sizeof(cred)) ||
      cred.version != kCurrentVersion) {
    return HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID;
  }

  if (!IsCredentialIdValid(cred)) {
    LOG(ERROR) << "Hash verification failed.";
    return HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID;
  }

  return HasCredentialsResponse::SUCCESS;
}

CoseAlgorithmIdentifier U2fCommandProcessorGeneric::GetAlgorithm() {
  return CoseAlgorithmIdentifier::kRs256;
}

std::optional<brillo::SecureBlob>
U2fCommandProcessorGeneric::GetWebAuthnSecret() {
  std::optional<std::string> account_id = user_state_->GetUser();
  if (!account_id) {
    LOG(ERROR) << "Trying to get WebAuthnSecret when no present user.";
    return std::nullopt;
  }

  user_data_auth::GetWebAuthnSecretRequest request;
  request.mutable_account_id()->set_account_id(*account_id);
  user_data_auth::GetWebAuthnSecretReply reply;
  bool result = cryptohome_proxy_->GetWebAuthnSecret(
      request, &reply, /*error=*/nullptr, kCryptohomeTimeout.InMilliseconds());
  if (!result) {
    return std::nullopt;
  }

  if (reply.error() !=
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
    LOG(ERROR) << "GetWebAuthnSecret reply has error " << reply.error();
    return std::nullopt;
  }

  brillo::SecureBlob secret(reply.webauthn_secret());

  if (secret.size() != SHA256_DIGEST_LENGTH) {
    LOG(ERROR) << "WebAuthn auth time secret size is wrong.";
    return std::nullopt;
  }

  return secret;
}

}  // namespace u2f
