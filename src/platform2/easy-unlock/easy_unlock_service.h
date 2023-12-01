// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef EASY_UNLOCK_EASY_UNLOCK_SERVICE_H_
#define EASY_UNLOCK_EASY_UNLOCK_SERVICE_H_

#include <stdint.h>

#include <memory>
#include <vector>

#include <easy-unlock-crypto/service_impl.h>

namespace easy_unlock {

// Wrapper around actual EasyUnlock dbus service implementation.
// See ServiceImpl in easy_unlock_crypto repo for more information on the
// methods provided by this interface.
class Service {
 public:
  // Creates the service implementation to be used in production code.
  // Caller should take ownership.
  static std::unique_ptr<Service> Create();

  virtual ~Service() {}

  virtual void GenerateEcP256KeyPair(std::vector<uint8_t>* private_key,
                                     std::vector<uint8_t>* public_key) = 0;
  virtual std::vector<uint8_t> WrapPublicKey(
      easy_unlock_crypto::ServiceImpl::KeyAlgorithm algorithm,
      const std::vector<uint8_t>& public_key) = 0;
  virtual std::vector<uint8_t> PerformECDHKeyAgreement(
      const std::vector<uint8_t>& private_key,
      const std::vector<uint8_t>& public_key) = 0;
  virtual std::vector<uint8_t> CreateSecureMessage(
      const std::vector<uint8_t>& payload,
      const std::vector<uint8_t>& key,
      const std::vector<uint8_t>& associated_data,
      const std::vector<uint8_t>& public_metadata,
      const std::vector<uint8_t>& verification_key_id,
      const std::vector<uint8_t>& decryption_key_id,
      easy_unlock_crypto::ServiceImpl::EncryptionType encryption_type,
      easy_unlock_crypto::ServiceImpl::SignatureType signature_type) = 0;
  virtual std::vector<uint8_t> UnwrapSecureMessage(
      const std::vector<uint8_t>& secure_message,
      const std::vector<uint8_t>& key,
      const std::vector<uint8_t>& associated_data,
      easy_unlock_crypto::ServiceImpl::EncryptionType encryption_type,
      easy_unlock_crypto::ServiceImpl::SignatureType signature_type) = 0;
};

}  // namespace easy_unlock

#endif  // EASY_UNLOCK_EASY_UNLOCK_SERVICE_H_
