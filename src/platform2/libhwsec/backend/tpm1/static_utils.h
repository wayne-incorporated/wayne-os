// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_STATIC_UTILS_H_
#define LIBHWSEC_BACKEND_TPM1_STATIC_UTILS_H_

#include <cstdint>

#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <trousers/tss.h>

#include "libhwsec/overalls/overalls.h"
#include "libhwsec/status.h"

namespace hwsec {

// Size of the migration destination key to be generated. Note that the choice
// of this size is constrained by restrictions from the TPM 1.2 specs.
inline constexpr int kMigrationDestinationKeySizeBits = 2048;
inline constexpr int kMigrationDestinationKeySizeFlag = TSS_KEY_SIZE_2048;
inline constexpr int kMigrationDestinationKeySizeBytes =
    kMigrationDestinationKeySizeBits / 8;

// Size of the certified migratable key to be created. Note that the choice of
// this size is dictated by restrictions from the TPM 1.2 specs
inline constexpr int kCmkKeySizeBits = 2048;
inline constexpr int kCmkKeySizeFlag = TSS_KEY_SIZE_2048;
inline constexpr int kCmkKeySizeBytes = kCmkKeySizeBits / 8;
inline constexpr int kCmkPrivateKeySizeBytes = kCmkKeySizeBytes / 2;

// The RSA OAEP label parameter specified to be used by the TPM 1.2 specs (see
// TPM 1.2 Part 1 Section 31.1.1 "TPM_ES_RSAESOAEP_SHA1_MGF1").
inline constexpr char kTpmRsaOaepLabel[] = {'T', 'C', 'P', 'A'};

// Sizes of the two parts of the migrated CMK private key blob: as described in
// TPM 1.2 Part 3 Section 11.9 ("TPM_CMK_CreateBlob"), one part goes into the
// OAEP seed and the rest goes into the TPM_MIGRATE_ASYMKEY struct.
inline constexpr int kMigratedCmkPrivateKeySeedPartSizeBytes = 16;
inline constexpr int kMigratedCmkPrivateKeyRestPartSizeBytes = 112;
static_assert(kMigratedCmkPrivateKeySeedPartSizeBytes == SHA_DIGEST_LENGTH - 4,
              "Invalid private key seed part size constant");
static_assert(kMigratedCmkPrivateKeySeedPartSizeBytes +
                      kMigratedCmkPrivateKeyRestPartSizeBytes ==
                  kCmkPrivateKeySizeBytes,
              "Invalid private key part size constants");

// Size of the TPM_MIGRATE_ASYMKEY structure containing the part of the migrated
// private key blob.
inline constexpr int kTpmMigrateAsymkeyBlobSize =
    sizeof(TPM_PAYLOAD_TYPE) /* for payload */ +
    SHA_DIGEST_LENGTH /* for usageAuth.authdata */ +
    SHA_DIGEST_LENGTH /* for pubDataDigest.digest */ +
    sizeof(uint32_t) /* for partPrivKeyLen */ +
    kMigratedCmkPrivateKeyRestPartSizeBytes /* for *partPrivKey */;

StatusOr<crypto::ScopedRSA> ParseRsaFromTpmPubkeyBlob(
    overalls::Overalls& overalls, const brillo::Blob& pubkey);

StatusOr<crypto::ScopedRSA> ExtractCmkPrivateKeyFromMigratedBlob(
    overalls::Overalls& overalls,
    const brillo::Blob& migrated_cmk_key12_blob,
    const brillo::Blob& migration_random_blob,
    const brillo::Blob& cmk_pubkey,
    const brillo::Blob& cmk_pubkey_digest,
    const brillo::Blob& msa_composite_digest,
    RSA& migration_destination_rsa);

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_STATIC_UTILS_H_
