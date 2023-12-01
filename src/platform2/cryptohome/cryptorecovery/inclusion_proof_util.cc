// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/cryptorecovery/inclusion_proof_util.h"

#include <libhwsec-foundation/crypto/sha.h>

namespace cryptohome {
namespace cryptorecovery {

namespace {
constexpr int kLeafHashPrefix = 0;
constexpr int kNodeHashPrefix = 1;
}  // namespace

brillo::Blob HashLeaf(const brillo::Blob& leaf_text) {
  brillo::Blob prefix;
  prefix.push_back(kLeafHashPrefix);
  return hwsec_foundation::Sha256(brillo::CombineBlobs({prefix, leaf_text}));
}

brillo::Blob HashChildren(const brillo::Blob& left, const brillo::Blob& right) {
  brillo::Blob prefix;
  prefix.push_back(kNodeHashPrefix);
  return hwsec_foundation::Sha256(brillo::CombineBlobs({prefix, left, right}));
}

}  // namespace cryptorecovery
}  // namespace cryptohome
