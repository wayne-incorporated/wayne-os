// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/fido/ec_public_key.h"

#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <base/containers/span.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <chromeos/cbor/reader.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include "cryptohome/fido/fido_constants.h"

namespace cryptohome {
namespace fido_device {

std::unique_ptr<ECPublicKey> ECPublicKey::ParseECPublicKey(
    base::span<const uint8_t> cose_encoded_public_key) {
  std::unique_ptr<ECPublicKey> ec_key(new ECPublicKey());
  if (!ec_key->ParseCOSE(cose_encoded_public_key))
    return nullptr;

  // Save the cose string.
  std::vector<uint8_t> bytes(cose_encoded_public_key.begin(),
                             cose_encoded_public_key.end());
  ec_key->SetCOSEKey(bytes);

  return ec_key;
}

ECPublicKey::ECPublicKey() {}

std::vector<uint8_t> ECPublicKey::EncodeAsCOSEKey() const {
  return cose_encoding_;
}

void ECPublicKey::SetCOSEKey(const std::vector<uint8_t> cose_key) {
  cose_encoding_ = cose_key;
}

bool ECPublicKey::ParseCOSE(base::span<const uint8_t> bytes) {
  size_t bytes_read;
  std::optional<cbor::Value> value = cbor::Reader::Read(bytes, &bytes_read);

  if (!value || !value->is_map()) {
    LOG(ERROR) << "Failed to parse public key, "
               << "COSE key should be a valid CBOR map";
    return false;
  }

  auto& cose_key = value->GetMap();

  // This is the only format we support now.
  for (const auto& pair : std::vector<std::pair<int, int>>({
           {1 /* key type */, 2 /* elliptic curve, uncompressed */},
           {3 /* algorithm */,
            static_cast<int>(CoseAlgorithmIdentifier::kCoseEs256)},
           {-1 /* curve */, 1 /* P-256 */},
       })) {
    auto it = cose_key.find(cbor::Value(pair.first));
    if (it == cose_key.end() || !it->second.is_integer() ||
        it->second.GetInteger() != pair.second) {
      LOG(ERROR) << "Failed to parse COSE when parsing key: "
                 << it->first.GetInteger()
                 << " value: " << it->second.GetInteger()
                 << ", only uncompressed EC P-256 public key is supported";
      return false;
    }
  }

  algorithm_ = kEccAlgName;

  // See https://tools.ietf.org/html/rfc8152#section-13.1.1
  const auto& x_it = cose_key.find(cbor::Value(-2));
  const auto& y_it = cose_key.find(cbor::Value(-3));

  if (x_it == cose_key.end() || y_it == cose_key.end() ||
      !x_it->second.is_bytestring() || !y_it->second.is_bytestring()) {
    return false;
  }
  x_ = x_it->second.GetBytestring();
  y_ = y_it->second.GetBytestring();
  return true;
}

bool ECPublicKey::DumpToDer(brillo::SecureBlob* der) {
  crypto::ScopedEC_Key pub_key = GetEC_KEY();
  if (!pub_key) {
    LOG(ERROR) << "Failed to create public key";
    return false;
  }

  int pub_key_len = i2d_EC_PUBKEY(pub_key.get(), NULL /* get size */);
  if (pub_key_len <= 0) {
    LOG(ERROR) << "Invalid EC_PUBKEY length: " << pub_key_len;
    return false;
  }

  der->resize(pub_key_len);
  unsigned char* der_buffer = der->data();
  pub_key_len = i2d_EC_PUBKEY(pub_key.get(), &der_buffer);
  if (pub_key_len < 0) {
    LOG(ERROR) << "Failed to encode to DER format.";
    return false;
  }
  der->resize(pub_key_len);
  return true;
}

crypto::ScopedEC_Key ECPublicKey::GetEC_KEY() const {
  crypto::ScopedEC_Key ecc_key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  const EC_GROUP* group = EC_KEY_get0_group(ecc_key.get());
  crypto::ScopedEC_POINT public_key(EC_POINT_new(group));

  crypto::ScopedBIGNUM x(BN_bin2bn(x_.data(), x_.size(), nullptr));
  crypto::ScopedBIGNUM y(BN_bin2bn(y_.data(), y_.size(), nullptr));

  if (!EC_POINT_set_affine_coordinates_GFp(group, public_key.get(), x.release(),
                                           y.release(), nullptr)) {
    LOG(ERROR) << "Failed to set affine coordinates GFp.";
    return nullptr;
  }
  if (!EC_KEY_set_public_key(ecc_key.get(), public_key.release())) {
    LOG(ERROR) << "Failed to set public key for EC_KEY.";
    return nullptr;
  }
  EC_KEY_set_asn1_flag(ecc_key.get(), OPENSSL_EC_NAMED_CURVE);

  if (!EC_KEY_check_key(ecc_key.get())) {
    LOG(ERROR) << "Invalid EC public key, please make sure the public key is "
               << "on curve.";
    return nullptr;
  }
  return ecc_key;
}

std::string ECPublicKey::ToString() {
  std::stringstream ss;
  ss << "EC P256 public key, x = " << base::HexEncode(x_.data(), x_.size())
     << ", y = " << base::HexEncode(y_.data(), y_.size());

  return ss.str();
}

BinaryValue ECPublicKey::GetX() const {
  return x_;
}

BinaryValue ECPublicKey::GetY() const {
  return y_;
}

std::optional<int> ECPublicKey::GetAlgorithmNid() const {
  if (algorithm_ == "ES256")
    return NID_X9_62_prime256v1;

  return std::nullopt;
}

}  // namespace fido_device
}  // namespace cryptohome
