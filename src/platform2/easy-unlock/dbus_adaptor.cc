// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "easy-unlock/dbus_adaptor.h"

#include <utility>

#include <base/check.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>

#include "easy-unlock/easy_unlock_service.h"

namespace easy_unlock {

namespace {

// Converts encryption type string to ServiceImpl::EncryptionType enum.
bool ConvertEncryptionType(
    const std::string& encryption_type_str,
    easy_unlock_crypto::ServiceImpl::EncryptionType* type) {
  if (encryption_type_str == kEncryptionTypeNone) {
    *type = easy_unlock_crypto::ServiceImpl::ENCRYPTION_TYPE_NONE;
    return true;
  }

  if (encryption_type_str == kEncryptionTypeAES256CBC) {
    *type = easy_unlock_crypto::ServiceImpl::ENCRYPTION_TYPE_AES_256_CBC;
    return true;
  }

  return false;
}

// Converts signature type string to ServiceImpl::SignatureType enum.
bool ConvertSignatureType(
    const std::string& signature_type_str,
    easy_unlock_crypto::ServiceImpl::SignatureType* type) {
  if (signature_type_str == kSignatureTypeECDSAP256SHA256) {
    *type = easy_unlock_crypto::ServiceImpl::SIGNATURE_TYPE_ECDSA_P256_SHA256;
    return true;
  }

  if (signature_type_str == kSignatureTypeHMACSHA256) {
    *type = easy_unlock_crypto::ServiceImpl::SIGNATURE_TYPE_HMAC_SHA256;
    return true;
  }

  return false;
}

// Reads public key algorithm string passed to DBus method call and converts
// it to ServiceImpl::KeyAlgorithm enum. Returns whether the parameter
// was successfully read and converted.
bool ConvertKeyAlgorithm(
    const std::string& algorithm_str,
    easy_unlock_crypto::ServiceImpl::KeyAlgorithm* algorithm) {
  if (algorithm_str == kKeyAlgorithmRSA) {
    *algorithm = easy_unlock_crypto::ServiceImpl::KEY_ALGORITHM_RSA;
    return true;
  }

  if (algorithm_str == kKeyAlgorithmECDSA) {
    *algorithm = easy_unlock_crypto::ServiceImpl::KEY_ALGORITHM_ECDSA;
    return true;
  }

  return false;
}

}  // namespace

DBusAdaptor::DBusAdaptor(const scoped_refptr<dbus::Bus>& bus,
                         easy_unlock::Service* service)
    : service_impl_(service),
      dbus_object_(
          nullptr, bus, dbus::ObjectPath(easy_unlock::kEasyUnlockServicePath)) {
  CHECK(service_impl_) << "Service implementation not passed to DBus adaptor";
}

DBusAdaptor::~DBusAdaptor() {}

void DBusAdaptor::Register(CompletionAction callback) {
  brillo::dbus_utils::DBusInterface* interface =
      dbus_object_.AddOrGetInterface(kEasyUnlockServiceInterface);

  interface->AddSimpleMethodHandler(kGenerateEcP256KeyPairMethod,
                                    base::Unretained(this),
                                    &DBusAdaptor::GenerateEcP256KeyPair);
  interface->AddSimpleMethodHandler(kWrapPublicKeyMethod,
                                    base::Unretained(this),
                                    &DBusAdaptor::WrapPublicKey);
  interface->AddSimpleMethodHandler(kPerformECDHKeyAgreementMethod,
                                    base::Unretained(this),
                                    &DBusAdaptor::PerformECDHKeyAgreement);
  interface->AddSimpleMethodHandler(kCreateSecureMessageMethod,
                                    base::Unretained(this),
                                    &DBusAdaptor::CreateSecureMessage);
  interface->AddSimpleMethodHandler(kUnwrapSecureMessageMethod,
                                    base::Unretained(this),
                                    &DBusAdaptor::UnwrapSecureMessage);
  dbus_object_.RegisterAsync(std::move(callback));
}

void DBusAdaptor::GenerateEcP256KeyPair(std::vector<uint8_t>* private_key,
                                        std::vector<uint8_t>* public_key) {
  service_impl_->GenerateEcP256KeyPair(private_key, public_key);
}

std::vector<uint8_t> DBusAdaptor::WrapPublicKey(
    const std::string& algorithm_str, const std::vector<uint8_t>& public_key) {
  easy_unlock_crypto::ServiceImpl::KeyAlgorithm algorithm;
  if (!ConvertKeyAlgorithm(algorithm_str, &algorithm)) {
    LOG(ERROR) << "Invalid key algorithm";
    // TODO(tbarzic): Return error instead.
    return std::vector<uint8_t>();
  }

  return service_impl_->WrapPublicKey(algorithm, public_key);
}

std::vector<uint8_t> DBusAdaptor::PerformECDHKeyAgreement(
    const std::vector<uint8_t>& private_key,
    const std::vector<uint8_t>& public_key) {
  return service_impl_->PerformECDHKeyAgreement(private_key, public_key);
}

std::vector<uint8_t> DBusAdaptor::CreateSecureMessage(
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& associated_data,
    const std::vector<uint8_t>& public_metadata,
    const std::vector<uint8_t>& verification_key_id,
    const std::vector<uint8_t>& decryption_key_id,
    const std::string& encryption_type_str,
    const std::string& signature_type_str) {
  easy_unlock_crypto::ServiceImpl::EncryptionType encryption_type;
  easy_unlock_crypto::ServiceImpl::SignatureType signature_type;

  if (!ConvertEncryptionType(encryption_type_str, &encryption_type) ||
      !ConvertSignatureType(signature_type_str, &signature_type)) {
    LOG(ERROR) << "Invalid encryption or signature type";
    // TODO(tbarzic): Return error here.
    return std::vector<uint8_t>();
  }

  return service_impl_->CreateSecureMessage(
      payload, key, associated_data, public_metadata, verification_key_id,
      decryption_key_id, encryption_type, signature_type);
}

std::vector<uint8_t> DBusAdaptor::UnwrapSecureMessage(
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& associated_data,
    const std::string& encryption_type_str,
    const std::string& signature_type_str) {
  easy_unlock_crypto::ServiceImpl::EncryptionType encryption_type;
  easy_unlock_crypto::ServiceImpl::SignatureType signature_type;

  if (!ConvertEncryptionType(encryption_type_str, &encryption_type) ||
      !ConvertSignatureType(signature_type_str, &signature_type)) {
    LOG(ERROR) << "Invalid encryption or signature type";
    // TODO(tbarzic): Return error here.
    return std::vector<uint8_t>();
  }

  return service_impl_->UnwrapSecureMessage(message, key, associated_data,
                                            encryption_type, signature_type);
}

}  // namespace easy_unlock
