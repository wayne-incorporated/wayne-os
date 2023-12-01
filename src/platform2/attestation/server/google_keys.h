// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_SERVER_GOOGLE_KEYS_H_
#define ATTESTATION_SERVER_GOOGLE_KEYS_H_

#include <array>
#include <string>

#include <attestation/proto_bindings/google_key.pb.h>
#include <attestation/proto_bindings/interface.pb.h>

namespace attestation {

// A class that manages the public keys along with their key IDs the attestation
// service uses.
class GoogleKeys {
 public:
  GoogleKeys();
  explicit GoogleKeys(const DefaultGoogleRsaPublicKeySet& default_key_set);
  ~GoogleKeys() = default;

  // Copyable and movable with the default behavior.
  GoogleKeys(const GoogleKeys&) = default;
  GoogleKeys& operator=(const GoogleKeys&) = default;
  GoogleKeys(GoogleKeys&&) = default;
  GoogleKeys& operator=(GoogleKeys&&) = default;

  const GoogleRsaPublicKey& ca_encryption_key(ACAType aca_type) const;
  const GoogleRsaPublicKey& va_signing_key(VAType va_type) const;
  const GoogleRsaPublicKey& va_encryption_key(VAType va_type) const;

 private:
  std::array<GoogleRsaPublicKey, ACAType_ARRAYSIZE> ca_encryption_keys_;
  std::array<GoogleRsaPublicKey, VAType_ARRAYSIZE> va_signing_keys_;
  std::array<GoogleRsaPublicKey, VAType_ARRAYSIZE> va_encryption_keys_;
};

}  // namespace attestation

#endif  // ATTESTATION_SERVER_GOOGLE_KEYS_H_
