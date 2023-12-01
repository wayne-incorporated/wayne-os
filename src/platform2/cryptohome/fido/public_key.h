// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_FIDO_PUBLIC_KEY_H_
#define CRYPTOHOME_FIDO_PUBLIC_KEY_H_

#include <stdint.h>
#include <string>
#include <vector>

#include <brillo/secure_blob.h>

#include "base/component_export.h"

namespace cryptohome {
namespace fido_device {

// https://www.w3.org/TR/2017/WD-webauthn-20170505/#sec-attestation-data.
class PublicKey {
 public:
  PublicKey() = default;
  PublicKey(const PublicKey&) = delete;
  PublicKey& operator=(const PublicKey&) = delete;
  // public key
  virtual ~PublicKey() = default;

  // The credential public key as a COSE_Key map as defined in Section 7
  // of https://tools.ietf.org/html/rfc8152.
  virtual std::vector<uint8_t> EncodeAsCOSEKey() const = 0;

  // Convert the public key to DER format for TPM.
  virtual bool DumpToDer(brillo::SecureBlob* der);

  virtual std::string GetAlgorithmName();

  virtual std::string ToString();

 protected:
  explicit PublicKey(std::string algorithm);

  std::string algorithm_;
};

}  // namespace fido_device
}  // namespace cryptohome

#endif  // CRYPTOHOME_FIDO_PUBLIC_KEY_H_
