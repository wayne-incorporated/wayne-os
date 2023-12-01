// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymint/context/arc_keymint_context.h"

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/base64.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <keymaster/android_keymaster_utils.h>
#include <keymaster/key_blob_utils/integrity_assured_key_blob.h>
#include <keymaster/key_blob_utils/software_keyblobs.h>
#include <mojo/cert_store.mojom.h>
#include <openssl/evp.h>

#include "arc/keymint/context/chaps_client.h"
#include "arc/keymint/context/openssl_utils.h"

namespace arc::keymint::context {

namespace {

bool DeserializeKeyMaterialToBlob(const std::string& key_material,
                                  ::keymaster::KeymasterKeyBlob* output) {
  if (!output->Reset(key_material.size())) {
    return false;
  }

  uint8_t* end = std::copy(key_material.begin(), key_material.end(),
                           output->writable_data());
  CHECK_EQ(end - output->key_material, output->key_material_size);
  return true;
}

bool DeserializeKeyDataToBlob(const KeyData& key_data,
                              ::keymaster::KeymasterKeyBlob* output) {
  if (!output->Reset(key_data.ByteSizeLong())) {
    return false;
  }
  uint8_t* end =
      key_data.SerializeWithCachedSizesToArray(output->writable_data());
  return (end - output->key_material) == output->key_material_size;
}

void SerializeAuthorizationSet(const ::keymaster::AuthorizationSet& auth_set,
                               std::string* output) {
  output->resize(auth_set.SerializedSize());
  uint8_t* buffer = reinterpret_cast<uint8_t*>(std::data(*output));
  auth_set.Serialize(buffer, buffer + output->size());
}

bool DeserializeAuthorizationSet(const std::string& serialized_auth_set,
                                 ::keymaster::AuthorizationSet* output) {
  std::string mutable_auth_set(serialized_auth_set);
  const uint8_t* buffer =
      reinterpret_cast<uint8_t*>(std::data(mutable_auth_set));
  return output->Deserialize(&buffer, buffer + serialized_auth_set.size());
}

brillo::Blob SerializeAuthorizationSetToBlob(
    const ::keymaster::AuthorizationSet& authorization_set) {
  brillo::Blob blob(authorization_set.SerializedSize(), 0);
  authorization_set.Serialize(blob.data(), blob.data() + blob.size());
  return blob;
}

bool UpgradeIntegerTag(keymaster_tag_t tag,
                       uint32_t value,
                       ::keymaster::AuthorizationSet* authorization_set,
                       bool* authorization_set_did_change) {
  *authorization_set_did_change = false;
  int tag_index = authorization_set->find(tag);
  if (tag_index == -1) {
    keymaster_key_param_t key_param;
    key_param.tag = tag;
    key_param.integer = value;
    authorization_set->push_back(key_param);
    *authorization_set_did_change = true;
    return true;
  }

  if (authorization_set->params[tag_index].integer > value) {
    return false;
  }

  if (authorization_set->params[tag_index].integer != value) {
    authorization_set->params[tag_index].integer = value;
    *authorization_set_did_change = true;
  }
  return true;
}

KeyData PackToArcKeyData(const ::keymaster::KeymasterKeyBlob& key_material,
                         const ::keymaster::AuthorizationSet& hw_enforced,
                         const ::keymaster::AuthorizationSet& sw_enforced) {
  KeyData key_data;

  // Copy key material.
  key_data.mutable_arc_key()->set_key_material(key_material.key_material,
                                               key_material.key_material_size);

  // Serialize hardware enforced authorization set.
  SerializeAuthorizationSet(hw_enforced, key_data.mutable_hw_enforced_tags());

  // Serialize software enforced authorization set.
  SerializeAuthorizationSet(sw_enforced, key_data.mutable_sw_enforced_tags());

  return key_data;
}

std::optional<KeyData> PackToChromeOsKeyData(
    const arc::keymint::mojom::KeyDataPtr& mojo_key_data,
    const ::keymaster::AuthorizationSet& hw_enforced,
    const ::keymaster::AuthorizationSet& sw_enforced) {
  KeyData key_data;

  // Copy key data.
  if (mojo_key_data->is_chaps_key_data()) {
    key_data.mutable_chaps_key()->set_id(
        mojo_key_data->get_chaps_key_data()->id);
    key_data.mutable_chaps_key()->set_label(
        mojo_key_data->get_chaps_key_data()->label);
    key_data.mutable_chaps_key()->set_slot(
        (ChapsKeyData::Slot)mojo_key_data->get_chaps_key_data()->slot);
  } else {
    return std::nullopt;
  }

  // Serialize hardware enforced authorization set.
  SerializeAuthorizationSet(hw_enforced, key_data.mutable_hw_enforced_tags());

  // Serialize software enforced authorization set.
  SerializeAuthorizationSet(sw_enforced, key_data.mutable_sw_enforced_tags());

  return key_data;
}

bool UnpackFromKeyData(const KeyData& key_data,
                       ::keymaster::KeymasterKeyBlob* key_material,
                       ::keymaster::AuthorizationSet* hw_enforced,
                       ::keymaster::AuthorizationSet* sw_enforced) {
  // For ARC keys, deserialize the actual key material into |key_material|.
  if (key_data.data_case() == KeyData::DataCase::kArcKey &&
      !DeserializeKeyMaterialToBlob(key_data.arc_key().key_material(),
                                    key_material)) {
    return false;
  }
  // For any other key type, store the full |key_data| into |key_material|.
  if (key_data.data_case() != KeyData::DataCase::kArcKey &&
      !DeserializeKeyDataToBlob(key_data, key_material)) {
    return false;
  }

  // Deserialize hardware enforced authorization set.
  if (!DeserializeAuthorizationSet(key_data.hw_enforced_tags(), hw_enforced)) {
    return false;
  }

  // Deserialize software enforced authorization set.
  return DeserializeAuthorizationSet(key_data.sw_enforced_tags(), sw_enforced);
}

std::optional<keymaster_algorithm_t> FindAlgorithmTag(
    const ::keymaster::AuthorizationSet& hw_enforced,
    const ::keymaster::AuthorizationSet& sw_enforced) {
  keymaster_algorithm_t algorithm;
  if (!hw_enforced.GetTagValue(::keymaster::TAG_ALGORITHM, &algorithm) &&
      !sw_enforced.GetTagValue(::keymaster::TAG_ALGORITHM, &algorithm)) {
    return std::nullopt;
  }
  return algorithm;
}

std::optional<std::string> ExtractBase64Spki(
    const ::keymaster::KeymasterKeyBlob& key_material) {
  // Parse key material.
  const uint8_t* material = key_material.key_material;
  EVP_PKEY* pkey = d2i_PrivateKey(EVP_PKEY_RSA, /*pkey=*/nullptr, &material,
                                  key_material.key_material_size);
  if (!pkey) {
    return std::nullopt;
  }
  std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> pkey_deleter(
      pkey, EVP_PKEY_free);

  // Retrieve DER subject public key info.
  int der_spki_length = i2d_PUBKEY(pkey, /*outp=*/nullptr);
  if (der_spki_length <= 0) {
    return std::nullopt;
  }

  brillo::Blob der_spki(der_spki_length, 0);
  uint8_t* der_spki_buffer = std::data(der_spki);
  int written_bytes = i2d_PUBKEY(pkey, &der_spki_buffer);
  if (written_bytes != der_spki_length) {
    return std::nullopt;
  }

  // Encode subject public key info to base 64.
  std::string der_spki_string(der_spki.begin(), der_spki.end());
  std::string base64_spki;
  base::Base64Encode(der_spki_string, &base64_spki);
  return base64_spki;
}

}  // namespace

ArcKeyMintContext::ArcKeyMintContext(::keymaster::KmVersion version)
    : PureSoftKeymasterContext(version),
      rsa_key_factory_(context_adaptor_.GetWeakPtr(), KM_ALGORITHM_RSA) {}

ArcKeyMintContext::~ArcKeyMintContext() = default;

void ArcKeyMintContext::set_placeholder_keys(
    std::vector<arc::keymint::mojom::ChromeOsKeyPtr> keys) {
  placeholder_keys_ = std::move(keys);
}

void ArcKeyMintContext::DeletePlaceholderKey(
    const arc::keymint::mojom::ChromeOsKeyPtr& key) const {
  std::vector<arc::keymint::mojom::ChromeOsKeyPtr>::iterator position =
      std::find(placeholder_keys_.begin(), placeholder_keys_.end(), key);
  if (position != placeholder_keys_.end()) {
    placeholder_keys_.erase(position);
  }
}

std::optional<arc::keymint::mojom::ChromeOsKeyPtr>
ArcKeyMintContext::FindPlaceholderKey(
    const ::keymaster::KeymasterKeyBlob& key_material) const {
  if (placeholder_keys_.empty()) {
    return std::nullopt;
  }

  std::optional<std::string> base64_spki = ExtractBase64Spki(key_material);
  if (!base64_spki.has_value()) {
    return std::nullopt;
  }

  for (const auto& cros_key : placeholder_keys_) {
    if (base64_spki.value() == cros_key->base64_subject_public_key_info) {
      LOG(INFO) << "Found the placeholder key";
      return cros_key->Clone();
    }
  }

  return std::nullopt;
}

std::optional<KeyData> ArcKeyMintContext::PackToKeyData(
    const ::keymaster::KeymasterKeyBlob& key_material,
    const ::keymaster::AuthorizationSet& hw_enforced,
    const ::keymaster::AuthorizationSet& sw_enforced) const {
  std::optional<arc::keymint::mojom::ChromeOsKeyPtr> cros_key =
      FindPlaceholderKey(key_material);
  if (!cros_key.has_value()) {
    return PackToArcKeyData(key_material, hw_enforced, sw_enforced);
  }

  std::optional<KeyData> key_data = PackToChromeOsKeyData(
      cros_key.value()->key_data->Clone(), hw_enforced, sw_enforced);

  // Ensure the placeholder of a Chrome OS key is only used once.
  if (key_data.has_value()) {
    DeletePlaceholderKey(cros_key.value());
  }

  return key_data;
}

keymaster_error_t ArcKeyMintContext::CreateKeyBlob(
    const ::keymaster::AuthorizationSet& key_description,
    const keymaster_key_origin_t origin,
    const ::keymaster::KeymasterKeyBlob& key_material,
    ::keymaster::KeymasterKeyBlob* key_blob,
    ::keymaster::AuthorizationSet* hw_enforced,
    ::keymaster::AuthorizationSet* sw_enforced) const {
  keymaster_error_t error =
      SetKeyBlobAuthorizations(key_description, origin, os_version_,
                               os_patchlevel_, hw_enforced, sw_enforced);
  if (error != KM_ERROR_OK) {
    return error;
  }

  ::keymaster::AuthorizationSet hidden;
  error = BuildHiddenAuthorizations(key_description, &hidden,
                                    ::keymaster::softwareRootOfTrust);
  if (error != KM_ERROR_OK) {
    return error;
  }

  return SerializeKeyDataBlob(key_material, hidden, *hw_enforced, *sw_enforced,
                              key_blob);
}

keymaster_error_t ArcKeyMintContext::ParseKeyBlob(
    const ::keymaster::KeymasterKeyBlob& key_blob,
    const ::keymaster::AuthorizationSet& additional_params,
    ::keymaster::UniquePtr<::keymaster::Key>* key) const {
  if (!key) {
    return KM_ERROR_OUTPUT_PARAMETER_NULL;
  }

  ::keymaster::AuthorizationSet hw_enforced;
  ::keymaster::AuthorizationSet sw_enforced;
  ::keymaster::KeymasterKeyBlob key_material;

  ::keymaster::AuthorizationSet hidden;
  keymaster_error_t error = BuildHiddenAuthorizations(
      additional_params, &hidden, ::keymaster::softwareRootOfTrust);
  if (error != KM_ERROR_OK) {
    return error;
  }

  error = DeserializeBlob(key_blob, hidden, &key_material, &hw_enforced,
                          &sw_enforced, key);
  if (error != KM_ERROR_OK) {
    return error;
  }
  if (*key) {
    return KM_ERROR_OK;
  }

  std::optional<keymaster_algorithm_t> algorithm =
      FindAlgorithmTag(hw_enforced, sw_enforced);
  if (!algorithm.has_value()) {
    return KM_ERROR_INVALID_ARGUMENT;
  }

  ::keymaster::KeyFactory* factory = GetKeyFactory(algorithm.value());
  return factory->LoadKey(std::move(key_material), additional_params,
                          std::move(hw_enforced), std::move(sw_enforced), key);
}

keymaster_error_t ArcKeyMintContext::UpgradeKeyBlob(
    const ::keymaster::KeymasterKeyBlob& key_blob,
    const ::keymaster::AuthorizationSet& upgrade_params,
    ::keymaster::KeymasterKeyBlob* upgraded_key) const {
  // Deserialize |key_blob| so it can be upgraded.
  ::keymaster::AuthorizationSet hidden;
  keymaster_error_t error = BuildHiddenAuthorizations(
      upgrade_params, &hidden, ::keymaster::softwareRootOfTrust);
  if (error != KM_ERROR_OK) {
    return error;
  }

  ::keymaster::AuthorizationSet hw_enforced;
  ::keymaster::AuthorizationSet sw_enforced;
  ::keymaster::KeymasterKeyBlob key_material;
  error = DeserializeBlob(key_blob, hidden, &key_material, &hw_enforced,
                          &sw_enforced, /*key=*/nullptr);
  if (error != KM_ERROR_OK) {
    return error;
  }

  // Try to upgrade system version and patchlevel, return if upgrade fails.
  bool os_version_did_change = false;
  bool patchlevel_did_change = false;
  if (!UpgradeIntegerTag(::keymaster::TAG_OS_VERSION, os_version_, &sw_enforced,
                         &os_version_did_change) ||
      !UpgradeIntegerTag(::keymaster::TAG_OS_PATCHLEVEL, os_patchlevel_,
                         &sw_enforced, &patchlevel_did_change)) {
    return KM_ERROR_INVALID_ARGUMENT;
  }

  // Do nothing if blob is already up to date.
  if (!os_version_did_change && !patchlevel_did_change) {
    return KM_ERROR_OK;
  }

  // Serialize the new blob into |upgraded_key|.
  return SerializeKeyDataBlob(key_material, hidden, hw_enforced, sw_enforced,
                              upgraded_key);
}

keymaster_error_t ArcKeyMintContext::DeserializeBlob(
    const ::keymaster::KeymasterKeyBlob& key_blob,
    const ::keymaster::AuthorizationSet& hidden,
    ::keymaster::KeymasterKeyBlob* key_material,
    ::keymaster::AuthorizationSet* hw_enforced,
    ::keymaster::AuthorizationSet* sw_enforced,
    ::keymaster::UniquePtr<::keymaster::Key>* key) const {
  keymaster_error_t error = DeserializeKeyDataBlob(
      key_blob, hidden, key_material, hw_enforced, sw_enforced, key);
  if (error == KM_ERROR_OK) {
    return error;
  }

  // Still need to parse insecure blobs when upgrading to the encrypted format.
  // TODO(b/151146402) drop support for insecure blobs.
  return DeserializeIntegrityAssuredBlob(key_blob, hidden, key_material,
                                         hw_enforced, sw_enforced);
}

keymaster_error_t ArcKeyMintContext::SerializeKeyDataBlob(
    const ::keymaster::KeymasterKeyBlob& key_material,
    const ::keymaster::AuthorizationSet& hidden,
    const ::keymaster::AuthorizationSet& hw_enforced,
    const ::keymaster::AuthorizationSet& sw_enforced,
    ::keymaster::KeymasterKeyBlob* key_blob) const {
  if (!key_blob) {
    return KM_ERROR_OUTPUT_PARAMETER_NULL;
  }

  std::optional<KeyData> key_data =
      PackToKeyData(key_material, hw_enforced, sw_enforced);
  if (!key_data.has_value()) {
    LOG(ERROR) << "Failed to package KeyData.";
    return KM_ERROR_UNKNOWN_ERROR;
  }

  // Serialize key data into the output |key_blob|.
  if (!SerializeKeyData(key_data.value(), hidden, key_blob)) {
    LOG(ERROR) << "Failed to serialize KeyData.";
    return KM_ERROR_UNKNOWN_ERROR;
  }

  return KM_ERROR_OK;
}

keymaster_error_t ArcKeyMintContext::DeserializeKeyDataBlob(
    const ::keymaster::KeymasterKeyBlob& key_blob,
    const ::keymaster::AuthorizationSet& hidden,
    ::keymaster::KeymasterKeyBlob* key_material,
    ::keymaster::AuthorizationSet* hw_enforced,
    ::keymaster::AuthorizationSet* sw_enforced,
    ::keymaster::UniquePtr<::keymaster::Key>* key) const {
  if (!key_material || !hw_enforced || !sw_enforced) {
    return KM_ERROR_OUTPUT_PARAMETER_NULL;
  }

  // Deserialize a KeyData object from the given |key_blob|.
  std::optional<KeyData> key_data = DeserializeKeyData(key_blob, hidden);
  if (!key_data.has_value() || key_data->data_case() == KeyData::DATA_NOT_SET) {
    LOG(ERROR) << "Failed to parse a KeyData from key blob.";
    return KM_ERROR_INVALID_KEY_BLOB;
  }

  // Unpack Keymaster structures from KeyData.
  if (!UnpackFromKeyData(key_data.value(), key_material, hw_enforced,
                         sw_enforced)) {
    LOG(ERROR) << "Failed to unpack key blob.";
    return KM_ERROR_INVALID_KEY_BLOB;
  }

  // Load it here if this is not an ARC key (it is a Chrome OS key).
  if (!key_data->has_arc_key() && key) {
    return LoadKey(std::move(key_data.value()), std::move(*hw_enforced),
                   std::move(*sw_enforced), key);
  }

  // Otherwise, return success and let Keymaster load ARC keys itself.
  return KM_ERROR_OK;
}

keymaster_error_t ArcKeyMintContext::LoadKey(
    KeyData&& key_data,
    ::keymaster::AuthorizationSet&& hw_enforced,
    ::keymaster::AuthorizationSet&& sw_enforced,
    ::keymaster::UniquePtr<::keymaster::Key>* key) const {
  std::optional<keymaster_algorithm_t> algorithm =
      FindAlgorithmTag(hw_enforced, sw_enforced);
  if (!algorithm.has_value()) {
    return KM_ERROR_INVALID_ARGUMENT;
  }

  switch (algorithm.value()) {
    case KM_ALGORITHM_RSA:
      return rsa_key_factory_.LoadKey(std::move(key_data),
                                      std::move(hw_enforced),
                                      std::move(sw_enforced), key);
    default:
      return KM_ERROR_UNSUPPORTED_ALGORITHM;
  }
}

bool ArcKeyMintContext::SerializeKeyData(
    const KeyData& key_data,
    const ::keymaster::AuthorizationSet& hidden,
    ::keymaster::KeymasterKeyBlob* key_blob) const {
  // Fetch key.
  ChapsClient chaps(context_adaptor_.GetWeakPtr(), ContextAdaptor::Slot::kUser);
  std::optional<brillo::SecureBlob> encryption_key =
      chaps.ExportOrGenerateEncryptionKey();
  if (!encryption_key.has_value()) {
    return false;
  }

  // Initialize a KeyData blob. Allocated blobs should offer the same guarantees
  // as brillo::SecureBlob (b/151103358).
  brillo::SecureBlob data(key_data.ByteSizeLong(), 0);
  key_data.SerializeWithCachedSizesToArray(data.data());

  // Encrypt the KeyData blob. As of Android R KeyStore's client ID and data
  // used in |auth_data| is empty. We still bind to it to comply with VTS tests.
  brillo::Blob auth_data = SerializeAuthorizationSetToBlob(hidden);
  std::optional<brillo::Blob> encrypted =
      Aes256GcmEncrypt(encryption_key.value(), auth_data, data);
  if (!encrypted.has_value()) {
    return false;
  }

  // Copy |encrypted| to output |key_blob|.
  if (!key_blob->Reset(encrypted->size())) {
    return false;
  }
  std::copy(encrypted->begin(), encrypted->end(), key_blob->writable_data());
  return true;
}

std::optional<KeyData> ArcKeyMintContext::DeserializeKeyData(
    const ::keymaster::KeymasterKeyBlob& key_blob,
    const ::keymaster::AuthorizationSet& hidden) const {
  // Fetch key.
  ChapsClient chaps(context_adaptor_.GetWeakPtr(), ContextAdaptor::Slot::kUser);
  std::optional<brillo::SecureBlob> encryption_key =
      chaps.ExportOrGenerateEncryptionKey();
  if (!encryption_key.has_value()) {
    return std::nullopt;
  }

  // Decrypt the KeyData blob.
  brillo::Blob encrypted(key_blob.begin(), key_blob.end());
  brillo::Blob auth_data = SerializeAuthorizationSetToBlob(hidden);
  std::optional<brillo::SecureBlob> unencrypted =
      Aes256GcmDecrypt(encryption_key.value(), auth_data, encrypted);
  if (!unencrypted.has_value()) {
    return std::nullopt;
  }

  // Parse the |unencrypted| blob into a KeyData object and return it.
  KeyData key_data;
  if (!key_data.ParseFromArray(unencrypted->data(), unencrypted->size())) {
    return std::nullopt;
  }

  return key_data;
}

brillo::Blob ArcKeyMintContext::TestSerializeAuthorizationSetToBlob(
    const ::keymaster::AuthorizationSet& authorization_set) {
  return SerializeAuthorizationSetToBlob(authorization_set);
}

}  // namespace arc::keymint::context
