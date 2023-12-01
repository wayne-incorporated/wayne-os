// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "easy-unlock/fake_easy_unlock_service.h"

#include <string>

#include <base/files/file_util.h>
#include <base/strings/stringprintf.h>

namespace {

const char kSecureMessageTemplate[] =
    "securemessage:{"
    "payload:%s,"
    "key:%s,"
    "associated_data:%s,"
    "public_metadata:%s,"
    "verification_key_id:%s,"
    "decryption_key_id:%s,"
    "encryption:%s,"
    "signature:%s"
    "}";

const char kUnwrappedMessageTemplate[] =
    "unwrappedmessage:{"
    "original:%s,"
    "key:%s,"
    "associated_data:%s,"
    "encryption:%s,"
    "signature:%s"
    "}";

std::string Uint8VectorAsString(const std::vector<uint8_t>& data) {
  return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

std::vector<uint8_t> StringAsUint8Vector(const std::string& data) {
  return std::vector<uint8_t>(data.c_str(), data.c_str() + data.length());
}

std::string EncryptionTypeAsString(
    easy_unlock_crypto::ServiceImpl::EncryptionType type) {
  switch (type) {
    case easy_unlock_crypto::ServiceImpl::ENCRYPTION_TYPE_NONE:
      return "NONE";
    case easy_unlock_crypto::ServiceImpl::ENCRYPTION_TYPE_AES_256_CBC:
      return "AES";
    default:
      return "";
  }
}

std::string SignatureTypeAsString(
    easy_unlock_crypto::ServiceImpl::SignatureType type) {
  switch (type) {
    case easy_unlock_crypto::ServiceImpl::SIGNATURE_TYPE_ECDSA_P256_SHA256:
      return "ECDSA_P256";
    case easy_unlock_crypto::ServiceImpl::SIGNATURE_TYPE_HMAC_SHA256:
      return "HMAC";
    default:
      return "";
  }
}

std::string KeyAlgorithmAsString(
    easy_unlock_crypto::ServiceImpl::KeyAlgorithm type) {
  switch (type) {
    case easy_unlock_crypto::ServiceImpl::KEY_ALGORITHM_ECDSA:
      return "ECDSA";
    case easy_unlock_crypto::ServiceImpl::KEY_ALGORITHM_RSA:
      return "RSA";
    default:
      return "";
  }
}

}  // namespace

namespace easy_unlock {

FakeService::FakeService() : private_key_count_(0), public_key_count_(0) {}

FakeService::~FakeService() {}

void FakeService::GenerateEcP256KeyPair(std::vector<uint8_t>* private_key,
                                        std::vector<uint8_t>* public_key) {
  *private_key = StringAsUint8Vector(
      base::StringPrintf("private_key_%d", ++private_key_count_));
  *public_key = StringAsUint8Vector(
      base::StringPrintf("public_key_%d", ++public_key_count_));
}

std::vector<uint8_t> FakeService::WrapPublicKey(
    easy_unlock_crypto::ServiceImpl::KeyAlgorithm algorithm,
    const std::vector<uint8_t>& public_key) {
  return StringAsUint8Vector(base::StringPrintf(
      "public_key_%s_%s", KeyAlgorithmAsString(algorithm).c_str(),
      Uint8VectorAsString(public_key).c_str()));
}

std::vector<uint8_t> FakeService::PerformECDHKeyAgreement(
    const std::vector<uint8_t>& private_key,
    const std::vector<uint8_t>& public_key) {
  return StringAsUint8Vector(
      base::StringPrintf("secret_key:{private_key:%s,public_key:%s}",
                         Uint8VectorAsString(private_key).c_str(),
                         Uint8VectorAsString(public_key).c_str()));
}

std::vector<uint8_t> FakeService::CreateSecureMessage(
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& associated_data,
    const std::vector<uint8_t>& public_metadata,
    const std::vector<uint8_t>& verification_key_id,
    const std::vector<uint8_t>& decryption_key_id,
    easy_unlock_crypto::ServiceImpl::EncryptionType encryption_type,
    easy_unlock_crypto::ServiceImpl::SignatureType signature_type) {
  return StringAsUint8Vector(base::StringPrintf(
      kSecureMessageTemplate, Uint8VectorAsString(payload).c_str(),
      Uint8VectorAsString(key).c_str(),
      Uint8VectorAsString(associated_data).c_str(),
      Uint8VectorAsString(public_metadata).c_str(),
      Uint8VectorAsString(verification_key_id).c_str(),
      Uint8VectorAsString(decryption_key_id).c_str(),
      EncryptionTypeAsString(encryption_type).c_str(),
      SignatureTypeAsString(signature_type).c_str()));
}

std::vector<uint8_t> FakeService::UnwrapSecureMessage(
    const std::vector<uint8_t>& secure_message,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& associated_data,
    easy_unlock_crypto::ServiceImpl::EncryptionType encryption_type,
    easy_unlock_crypto::ServiceImpl::SignatureType signature_type) {
  return StringAsUint8Vector(base::StringPrintf(
      kUnwrappedMessageTemplate, Uint8VectorAsString(secure_message).c_str(),
      Uint8VectorAsString(key).c_str(),
      Uint8VectorAsString(associated_data).c_str(),
      EncryptionTypeAsString(encryption_type).c_str(),
      SignatureTypeAsString(signature_type).c_str()));
}

}  // namespace easy_unlock
