// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_BLOCKS_AUTH_BLOCK_TYPE_H_
#define CRYPTOHOME_AUTH_BLOCKS_AUTH_BLOCK_TYPE_H_

namespace cryptohome {

// List of all the possible auth block types. Used to construct the correct
// AuthBlock type during key derivation and key creation.
// AuthBlockType is used in constructing the correct histogram while logging to
// UMA. These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class AuthBlockType {
  kPinWeaver = 0,
  kChallengeCredential = 1,
  kDoubleWrappedCompat = 2,
  kTpmBoundToPcr = 3,
  kTpmNotBoundToPcr = 4,
  kScrypt = 5,
  kCryptohomeRecovery = 6,
  kTpmEcc = 7,
  kFingerprint = 8,
};

// The highest auth block type enum value.
inline constexpr auto kAuthBlockTypeMaxValue = AuthBlockType::kFingerprint;

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_BLOCKS_AUTH_BLOCK_TYPE_H_
