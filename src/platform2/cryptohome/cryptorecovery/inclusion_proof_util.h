// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CRYPTORECOVERY_INCLUSION_PROOF_UTIL_H_
#define CRYPTOHOME_CRYPTORECOVERY_INCLUSION_PROOF_UTIL_H_

#include <string>

#include <brillo/secure_blob.h>

#include "cryptohome/cryptorecovery/recovery_crypto_util.h"

namespace cryptohome {
namespace cryptorecovery {

constexpr char kInclusionProofSigSplit[] = "\n\n";
constexpr char kInclusionProofNewline[] = "\n";
constexpr char kInclusionProofSigPrefix[] = "— ";
constexpr char kInclusionProofSigNameSplit[] = " ";

// Checkpoint represents a minimal log checkpoint (STH).
struct Checkpoint {
  // Origin is the string identifying the log which issued this checkpoint.
  std::string origin;
  // Size is the number of entries in the log at this checkpoint.
  int64_t size;
  // Hash is the hash which commits to the contents of the entire log.
  brillo::Blob hash;
};

// HashLeaf computes the hash of a leaf that exists.
brillo::Blob HashLeaf(const brillo::Blob& leaf_text);

// HashChildren computes interior nodes.
brillo::Blob HashChildren(const brillo::Blob& left, const brillo::Blob& right);

}  // namespace cryptorecovery
}  // namespace cryptohome

#endif  // CRYPTOHOME_CRYPTORECOVERY_INCLUSION_PROOF_UTIL_H_
