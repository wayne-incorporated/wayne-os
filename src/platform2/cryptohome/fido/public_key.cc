// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/fido/public_key.h"

#include <base/strings/string_number_conversions.h>
#include <sstream>
#include <utility>

namespace cryptohome {
namespace fido_device {

std::string PublicKey::GetAlgorithmName() {
  return algorithm_;
}

bool PublicKey::DumpToDer(brillo::SecureBlob* der) {
  return false;
}

std::string PublicKey::ToString() {
  std::stringstream ss;
  ss << "algorithm: " << algorithm_ << ", "
     << "COSE public key: "
     << base::HexEncode(EncodeAsCOSEKey().data(), EncodeAsCOSEKey().size());

  return ss.str();
}

PublicKey::PublicKey(std::string algorithm)
    : algorithm_(std::move(algorithm)) {}

}  // namespace fido_device
}  // namespace cryptohome
