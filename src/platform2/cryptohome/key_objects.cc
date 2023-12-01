// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/key_objects.h"

#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <libhwsec-foundation/crypto/hkdf.h>

using ::hwsec_foundation::Hkdf;
using ::hwsec_foundation::HkdfHash;

namespace cryptohome {

namespace {
// !!!WARNING!!!: This value must stay unchanged, for backwards compatibility.
constexpr char kUssCredentialSecretHkdfInfo[] = "cryptohome USS credential";
}  // namespace

std::optional<brillo::SecureBlob> KeyBlobs::DeriveUssCredentialSecret() const {
  if (!vkk_key.has_value() || vkk_key.value().empty()) {
    LOG(ERROR) << "Missing input secret for deriving a USS credential secret";
    return std::nullopt;
  }
  brillo::SecureBlob uss_credential_secret;
  if (!Hkdf(HkdfHash::kSha256, /*key=*/vkk_key.value(),
            /*info=*/brillo::SecureBlob(kUssCredentialSecretHkdfInfo),
            /*salt=*/brillo::SecureBlob(),
            /*result_len=*/0, &uss_credential_secret)) {
    LOG(ERROR) << "USS credential secret HKDF derivation failed";
    return std::nullopt;
  }
  CHECK(!uss_credential_secret.empty());
  return uss_credential_secret;
}

}  // namespace cryptohome
