// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CRYPTORECOVERY_INCLUSION_PROOF_H_
#define CRYPTOHOME_CRYPTORECOVERY_INCLUSION_PROOF_H_

#include "cryptohome/cryptorecovery/recovery_crypto_util.h"

namespace cryptohome {
namespace cryptorecovery {

// VerifyInclusion verifies the correctness of the inclusion proof for the leaf
// with the specified hash and index, relatively to the tree of the given size
// and root hash. Requires 0 <= index < size.
[[nodiscard]] bool VerifyInclusionProof(
    const LedgerSignedProof& ledger_signed_proof,
    const LedgerInfo& ledger_info);

}  // namespace cryptorecovery
}  // namespace cryptohome

#endif  // CRYPTOHOME_CRYPTORECOVERY_INCLUSION_PROOF_H_
