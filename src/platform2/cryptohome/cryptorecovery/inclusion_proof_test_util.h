// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CRYPTORECOVERY_INCLUSION_PROOF_TEST_UTIL_H_
#define CRYPTOHOME_CRYPTORECOVERY_INCLUSION_PROOF_TEST_UTIL_H_

#include <vector>

#include <libhwsec-foundation/crypto/big_num_util.h>

#include "cryptohome/cryptorecovery/recovery_crypto_util.h"

namespace cryptohome {
namespace cryptorecovery {

// Generates fake `ledger_signed_proof` data from the information provided, to
// be used for testing.
// The generated proof can be successfully verified with `VerifyInclusionProof`.
[[nodiscard]] bool GenerateFakeLedgerSignedProofForTesting(
    const std::vector<EC_KEY*>& fake_ledger_private_keys,
    const LedgerInfo& ledger_info,
    LedgerSignedProof* ledger_signed_proof);

}  // namespace cryptorecovery
}  // namespace cryptohome

#endif  // CRYPTOHOME_CRYPTORECOVERY_INCLUSION_PROOF_TEST_UTIL_H_
