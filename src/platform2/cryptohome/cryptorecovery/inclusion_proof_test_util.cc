// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/cryptorecovery/inclusion_proof_test_util.h"

#include <string>
#include <vector>

#include <base/big_endian.h>
#include <brillo/data_encoding.h>
#include <brillo/secure_blob.h>
#include <brillo/strings/string_utils.h>
#include <libhwsec-foundation/crypto/error_util.h>
#include <libhwsec-foundation/crypto/sha.h>

#include "cryptohome/cryptorecovery/inclusion_proof_util.h"
#include "cryptohome/cryptorecovery/recovery_crypto_util.h"

namespace cryptohome {
namespace cryptorecovery {

namespace {

// Generate a fake inclusion proof which includes the `leaf`. The fake tree
// looks like this:
//   `root_hash`
//     /      \
//    h0       h1
//   /   \    /  \
//  h00 h01  h10 h11
//   |   |   |    |
//   a   b   c  `leaf`
void GenerateFakeInclusionProofForTesting(
    const brillo::Blob leaf,
    std::vector<brillo::Blob>* inclusion_proof,
    int64_t* leaf_index,
    int64_t* size,
    brillo::Blob* root_hash) {
  const auto a = brillo::BlobFromString("leaf-a");
  const auto b = brillo::BlobFromString("leaf-b");
  const auto c = brillo::BlobFromString("leaf-c");

  const auto h00 = HashLeaf(a);
  const auto h01 = HashLeaf(b);
  const auto h10 = HashLeaf(c);
  const auto h11 = HashLeaf(leaf);

  const auto h0 = HashChildren(h00, h01);
  const auto h1 = HashChildren(h10, h11);

  *root_hash = HashChildren(h0, h1);

  *size = 4;                // The tree has 4 elements.
  *leaf_index = *size - 1;  // The `leaf` is the last element.

  // The inclusion proof needs the values of `h0` and `h10` to calculate the
  // `root_hash`.
  inclusion_proof->push_back(h10);
  inclusion_proof->push_back(h0);
}

bool SignForTesting(const std::string& text,
                    const std::vector<EC_KEY*>& private_keys,
                    const LedgerInfo& ledger_info,
                    std::string* signatures) {
  if (ledger_info.name.empty()) {
    LOG(ERROR) << "Ledger name is empty.";
    return false;
  }
  if (ledger_info.public_key->empty()) {
    LOG(ERROR) << "Ledger public key is not present.";
    return false;
  }

  brillo::SecureBlob text_hash = hwsec_foundation::Sha256(
      brillo::SecureBlob(text + kInclusionProofSigSplit[0]));

  for (EC_KEY* private_key : private_keys) {
    brillo::Blob signature_blob(ECDSA_size(private_key));
    unsigned int signature_length;

    if (ECDSA_sign(
            0, reinterpret_cast<const unsigned char*>(text_hash.char_data()),
            text_hash.size(), signature_blob.data(), &signature_length,
            private_key) != 1) {
      LOG(ERROR) << "Failed to sign data: "
                 << hwsec_foundation::GetOpenSSLErrors();
      return false;
    }
    std::string signature_bytes = brillo::BlobToString(signature_blob);
    // Truncate the buffer to the size returned by `ECDSA_sign()`.
    signature_bytes.resize(signature_length);

    std::string key_hash(sizeof(uint32_t), 0);
    base::WriteBigEndian(key_hash.data(), ledger_info.key_hash.value());
    // `signature_str` has the format: "{key_hash}{signature_bytes}".
    std::string signature_str = key_hash + signature_bytes;
    std::string base64_signature =
        brillo::data_encoding::Base64Encode(signature_str);
    // `signature_line` has the format:
    // "{prefix}{signature_name}{name_split}{base64_signature}".
    // Where:
    // - prefix = kInclusionProofSigPrefix,
    // - name_split = kInclusionProofSigNameSplit.
    std::string signature_line =
        std::string(kInclusionProofSigPrefix) + ledger_info.name +
        std::string(kInclusionProofSigNameSplit) + base64_signature;

    // Make sure that the signature ends with kInclusionProofNewline.
    *signatures += signature_line + kInclusionProofNewline;
  }

  return true;
}

// MarshalAndSignCheckPointForTesting takes a checkpoint object and returns a
// checkpoint string.
bool MarshalAndSignCheckPointForTesting(
    const Checkpoint& check_point,
    const std::vector<EC_KEY*>& fake_ledger_private_keys,
    const LedgerInfo& ledger_info,
    brillo::Blob* checkpoint_note_str) {
  std::string check_point_hash_str(
      brillo::data_encoding::Base64Encode(check_point.hash));
  // `text` has the format: "{origin}\n{size}\n{base64_hash}".
  std::string text = brillo::string_utils::Join(
      kInclusionProofNewline,
      {check_point.origin, std::to_string(check_point.size),
       check_point_hash_str});

  std::string signatures;
  if (!SignForTesting(text, fake_ledger_private_keys, ledger_info,
                      &signatures)) {
    return false;
  }

  // `checkpoint_note_str` has the format:
  // "{text}{kInclusionProofSigSplit}{signatures}".
  *checkpoint_note_str = brillo::BlobFromString(
      text + std::string(kInclusionProofSigSplit) + signatures);

  return true;
}

}  // namespace

bool GenerateFakeLedgerSignedProofForTesting(
    const std::vector<EC_KEY*>& fake_ledger_private_keys,
    const LedgerInfo& ledger_info,
    LedgerSignedProof* ledger_signed_proof) {
  // TODO(b/281486839): Pass metadata and create a real public ledger entry.
  brillo::Blob public_ledger_entry =
      brillo::BlobFromString("fake-public-entry");

  std::vector<brillo::Blob> inclusion_proof;
  int64_t leaf_index;
  int64_t size;
  brillo::Blob root_hash;
  GenerateFakeInclusionProofForTesting(
      /*leaf=*/public_ledger_entry, &inclusion_proof, &leaf_index, &size,
      &root_hash);

  LoggedRecord record{
      .public_ledger_entry = public_ledger_entry,
      // TODO(b/281486839): Pass metadata and create a real private log entry.
      .private_log_entry = brillo::BlobFromString("fake-private-entry"),
      .leaf_index = leaf_index,
  };
  ledger_signed_proof->logged_record = record;
  ledger_signed_proof->inclusion_proof = inclusion_proof;

  Checkpoint check_point{
      .origin = "fake-origin",
      .size = size,
      .hash = root_hash,
  };

  return MarshalAndSignCheckPointForTesting(
      check_point, fake_ledger_private_keys, ledger_info,
      &ledger_signed_proof->checkpoint_note);
}

}  // namespace cryptorecovery
}  // namespace cryptohome
