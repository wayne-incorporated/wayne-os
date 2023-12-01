// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "easy-unlock/easy_unlock_service.h"

#include <chromeos/dbus/service_constants.h>
#include <easy-unlock-crypto/service_impl.h>

namespace {

class ServiceImpl : public easy_unlock::Service {
 public:
  ServiceImpl() : crypto_service_(new easy_unlock_crypto::ServiceImpl()) {}
  ServiceImpl(const ServiceImpl&) = delete;
  ServiceImpl& operator=(const ServiceImpl&) = delete;

  virtual ~ServiceImpl() {}

  void GenerateEcP256KeyPair(std::vector<uint8_t>* private_key,
                             std::vector<uint8_t>* public_key) override {
    crypto_service_->GenerateEcP256KeyPair(private_key, public_key);
  }

  std::vector<uint8_t> WrapPublicKey(
      easy_unlock_crypto::ServiceImpl::KeyAlgorithm algorithm,
      const std::vector<uint8_t>& public_key) override {
    return crypto_service_->WrapPublicKey(algorithm, public_key);
  }

  std::vector<uint8_t> PerformECDHKeyAgreement(
      const std::vector<uint8_t>& private_key,
      const std::vector<uint8_t>& public_key) override {
    return crypto_service_->PerformECDHKeyAgreement(private_key, public_key);
  }

  std::vector<uint8_t> CreateSecureMessage(
      const std::vector<uint8_t>& payload,
      const std::vector<uint8_t>& key,
      const std::vector<uint8_t>& associated_data,
      const std::vector<uint8_t>& public_metadata,
      const std::vector<uint8_t>& verification_key_id,
      const std::vector<uint8_t>& decryption_key_id,
      easy_unlock_crypto::ServiceImpl::EncryptionType encryption_type,
      easy_unlock_crypto::ServiceImpl::SignatureType signature_type) override {
    return crypto_service_->CreateSecureMessage(
        payload, key, associated_data, public_metadata, verification_key_id,
        decryption_key_id, encryption_type, signature_type);
  }

  std::vector<uint8_t> UnwrapSecureMessage(
      const std::vector<uint8_t>& secure_message,
      const std::vector<uint8_t>& key,
      const std::vector<uint8_t>& associated_data,
      easy_unlock_crypto::ServiceImpl::EncryptionType encryption_type,
      easy_unlock_crypto::ServiceImpl::SignatureType signature_type) override {
    return crypto_service_->UnwrapSecureMessage(
        secure_message, key, associated_data, encryption_type, signature_type);
  }

 private:
  std::unique_ptr<easy_unlock_crypto::ServiceImpl> crypto_service_;
};

}  // namespace

namespace easy_unlock {

// static
std::unique_ptr<Service> Service::Create() {
  return std::unique_ptr<Service>(new ServiceImpl());
}

}  // namespace easy_unlock
