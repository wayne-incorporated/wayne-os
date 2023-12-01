// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/cryptorecovery/inclusion_proof.h"

#include <string>
#include <vector>

#include <absl/strings/numbers.h>
#include <base/base64.h>
#include <base/base64url.h>
#include <base/big_endian.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_tokenizer.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/data_encoding.h>
#include <brillo/secure_blob.h>
#include <brillo/strings/string_utils.h>
#include <crypto/scoped_openssl_types.h>
#include <libhwsec-foundation/crypto/error_util.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <openssl/ec.h>
#include <openssl/x509.h>

#include "cryptohome/cryptorecovery/inclusion_proof_util.h"
#include "cryptohome/cryptorecovery/recovery_crypto_util.h"

namespace cryptohome {
namespace cryptorecovery {

namespace {

// The number of checkpoint note fields should be 2: the signaute and the text.
constexpr int kCheckpointNoteSize = 2;
// The number of checkpoint fields should be 3: origin, size, hash.
constexpr int kCheckpointSize = 3;
// Signature hash is defined as the first 4 bytes from signature string from the
// server.
constexpr int kSignatureHashSize = 4;
// This value is reflecting to the value from the server side.
constexpr int kMaxSignatureNumber = 100;

struct Signature {
  std::string name;
  uint32_t key_hash = 0;
  bool is_verified = false;
  std::string openssl_error;
};

std::string SerializeSignatures(const std::vector<Signature> signatures) {
  std::string result;
  for (const auto& sig : signatures) {
    result += base::StringPrintf(
        "{name=%s,key_hash=%u,is_verified=%d,openssl_error=%s}",
        sig.name.c_str(), sig.key_hash, sig.is_verified,
        sig.openssl_error.c_str());
    result += ",";
  }
  return result;
}

// CalculateInnerProofSize breaks down inclusion proof for a leaf at the
// specified |index| in a tree of the specified |size| into 2 components. The
// splitting point between them is where paths to leaves |index| and |size-1|
// diverge. Returns lengths of the bottom proof parts.
int CalculateInnerProofSize(int index, int size) {
  DCHECK_GT(index, -1);
  DCHECK_GT(size, 0);
  int xor_number = index ^ (size - 1);
  int bits_number = 0;
  while (xor_number > 0) {
    xor_number = xor_number / 2;
    bits_number++;
  }
  return bits_number;
}

bool ReadSignatures(const std::string& text,
                    const std::string& signatures,
                    EC_KEY* ledger_key,
                    std::vector<Signature>* out_signatures) {
  base::StringTokenizer tokenizer(signatures, kInclusionProofNewline);
  tokenizer.set_options(base::StringTokenizer::RETURN_DELIMS);

  int num_sig = 0;
  while (tokenizer.GetNext()) {
    // `signature_line` has the format:
    // "{prefix}{signature_name}{name_split}{base64_signature}".
    // Where:
    // - prefix = kInclusionProofSigPrefix,
    // - name_split = kInclusionProofSigNameSplit.
    std::string signature_line = tokenizer.token();
    // Verify that the signature indeed ends with kInclusionProofNewline.
    if (!tokenizer.GetNext() || tokenizer.token() != kInclusionProofNewline) {
      LOG(ERROR) << "Failed to pull out one signature";
      return false;
    }
    num_sig++;

    // Avoid spending forever parsing a note with many signatures.
    if (num_sig > kMaxSignatureNumber)
      return false;

    if (!base::StartsWith(signature_line, kInclusionProofSigPrefix,
                          base::CompareCase::SENSITIVE)) {
      LOG(ERROR) << "No signature prefix is found.";
      return false;
    }

    // The ledger's name (signature_tokens[0]) could be parsed out with
    // separator of kInclusionProofSigNameSplit. And the signature and the key
    // hash (signature_tokens[1]) is located after kInclusionProofSigNameSplit.
    std::vector<std::string> signature_tokens = base::SplitString(
        signature_line.substr(strlen(kInclusionProofSigPrefix),
                              signature_line.length()),
        kInclusionProofSigNameSplit, base::KEEP_WHITESPACE,
        base::SPLIT_WANT_ALL);
    if (signature_tokens.size() != 2) {
      LOG(ERROR) << "No signature name split is found.";
      return false;
    }
    std::string signature_name = signature_tokens[0];
    // `signature_str` has the format: "{key_hash}{signature_bytes}".
    std::string signature_str;
    if (!brillo::data_encoding::Base64Decode(signature_tokens[1],
                                             &signature_str)) {
      LOG(ERROR) << "Failed to convert base64 string to string.";
      return false;
    }
    if (signature_str.length() < kSignatureHashSize) {
      LOG(ERROR) << "The length of the signature is not long enough.";
      return false;
    }
    uint32_t key_hash;
    base::ReadBigEndian(
        reinterpret_cast<const uint8_t*>(
            signature_str.substr(0, kSignatureHashSize).c_str()),
        &key_hash);

    brillo::SecureBlob text_hash = hwsec_foundation::Sha256(
        brillo::SecureBlob(text + kInclusionProofSigSplit[0]));
    signature_str = signature_str.substr(kSignatureHashSize);

    // Verify the signature and the hash.
    bool is_verified =
        ECDSA_verify(
            0, reinterpret_cast<const unsigned char*>(text_hash.char_data()),
            text_hash.size(),
            reinterpret_cast<const unsigned char*>(signature_str.c_str()),
            signature_str.length(), ledger_key) == 1;

    Signature signature{
        .name = signature_name,
        .key_hash = key_hash,
        .is_verified = is_verified,
    };
    if (!is_verified) {
      signature.openssl_error = hwsec_foundation::GetOpenSSLErrors();
    }

    out_signatures->push_back(signature);
  }

  return true;
}

bool VerifySignature(const std::string& text,
                     const std::string& signatures,
                     const LedgerInfo& ledger_info) {
  if (ledger_info.name.empty()) {
    LOG(ERROR) << "Ledger name is empty.";
    return false;
  }
  if (ledger_info.public_key->empty()) {
    LOG(ERROR) << "Ledger public key is not present.";
    return false;
  }

  // Import Public key of PKIX, ASN.1 DER form to EC_KEY.
  std::string ledger_public_key_decoded;
  if (!base::Base64UrlDecode(ledger_info.public_key.value().to_string(),
                             base::Base64UrlDecodePolicy::IGNORE_PADDING,
                             &ledger_public_key_decoded)) {
    LOG(ERROR) << "Failed at decoding from url base64.";
    return false;
  }
  const unsigned char* asn1_ptr =
      reinterpret_cast<const unsigned char*>(ledger_public_key_decoded.c_str());
  crypto::ScopedEC_KEY public_key(
      d2i_EC_PUBKEY(nullptr, &asn1_ptr, ledger_public_key_decoded.length()));
  if (!public_key.get() || !EC_KEY_check_key(public_key.get())) {
    LOG(ERROR) << "Failed to decode ECC public key.";
    return false;
  }

  std::vector<Signature> signatures_list;
  if (!ReadSignatures(text, signatures, public_key.get(), &signatures_list)) {
    LOG(ERROR) << "Failed to read signatures.";
    return false;
  }

  for (const auto& sig : signatures_list) {
    if (!sig.is_verified || sig.name != ledger_info.name ||
        sig.key_hash != ledger_info.key_hash.value()) {
      // Signature is not verified or unknown.
      continue;
    }

    // Known signature is verified.
    return true;
  }

  // No verified known signatures.
  LOG(ERROR) << "No verified known signatures found: "
             << SerializeSignatures(signatures_list);
  return false;
}

// ParseCheckpoint takes a raw checkpoint string and returns a parsed
// checkpoint, providing that:
// * at least one valid log signature is found; and
// * the checkpoint unmarshals correctly; and
// * TODO(b/281486839): verify that the log origin is as expected.
// Note: Only the ledger signature will be checked.
bool ParseCheckPoint(std::string checkpoint_note_str,
                     const LedgerInfo& ledger_info,
                     Checkpoint* check_point) {
  // `checkpoint_note_str` has the format:
  // "{text}{kInclusionProofSigSplit}{signatures}".
  std::vector<std::string> checkpoint_note_fields = brillo::string_utils::Split(
      checkpoint_note_str, kInclusionProofSigSplit, /*trim_whitespaces=*/false,
      /*purge_empty_strings=*/false);
  if (checkpoint_note_fields.size() != kCheckpointNoteSize) {
    LOG(ERROR) << "Checkpoint note is not valid.";
    return false;
  }
  std::string text = checkpoint_note_fields[0];
  std::string signatures = checkpoint_note_fields[1];
  if (!VerifySignature(text, signatures, ledger_info)) {
    LOG(ERROR) << "Failed to verify the signature of the checkpoint note.";
    return false;
  }

  // The ledger has signed this checkpoint. It is now safe to parse.
  // `checkpoint_fields` has the format: "{origin}\n{size}\n{base64_hash}".
  std::vector<std::string> checkpoint_fields =
      brillo::string_utils::Split(text, kInclusionProofNewline);
  if (checkpoint_fields.size() != kCheckpointSize) {
    LOG(ERROR) << "Checkpoint is not valid.";
    return false;
  }

  check_point->origin = checkpoint_fields[0];
  if (!base::StringToInt64(checkpoint_fields[1], &check_point->size)) {
    LOG(ERROR) << "Failed to convert checkpoint size string to int64_t.";
    return false;
  }
  if (check_point->size < 1) {
    LOG(ERROR) << "Checkpoint is not valid: size < 1.";
    return false;
  }
  std::string check_point_hash_str;
  if (!brillo::data_encoding::Base64Decode(checkpoint_fields[2],
                                           &check_point_hash_str)) {
    LOG(ERROR) << "Failed to decode base64 checkpoint hash.";
    return false;
  }
  check_point->hash = brillo::BlobFromString(check_point_hash_str);
  return true;
}

// CalculateRootHash calculates the expected root hash for a tree of the
// given size, provided a leaf index and leaf content with the corresponding
// inclusion proof. Requires 0 <= `leaf_index` < `size`.
bool CalculateRootHash(const brillo::Blob& leaf,
                       const std::vector<brillo::Blob>& inclusion_proof,
                       int64_t leaf_index,
                       int64_t size,
                       brillo::Blob* root_hash) {
  if (leaf_index < 0 || size < 1) {
    LOG(ERROR) << "Leaf index or inclusion proof size is not valid.";
    return false;
  }

  int64_t index = 0;
  int inner_proof_size = CalculateInnerProofSize(leaf_index, /*size=*/size);
  if (inner_proof_size > inclusion_proof.size()) {
    LOG(ERROR) << "Calculated inner proof size is not valid.";
    return false;
  }

  brillo::Blob seed = HashLeaf(leaf);
  while (index < inner_proof_size) {
    if (((leaf_index >> index) & 1) == 0) {
      seed = HashChildren(seed, inclusion_proof[index]);
    } else {
      seed = HashChildren(inclusion_proof[index], seed);
    }
    index++;
  }

  while (index < inclusion_proof.size()) {
    seed = HashChildren(inclusion_proof[index], seed);
    index++;
  }

  *root_hash = seed;

  return true;
}

}  // namespace

bool VerifyInclusionProof(const LedgerSignedProof& ledger_signed_proof,
                          const LedgerInfo& ledger_info) {
  // Parse checkpoint note.
  Checkpoint check_point;
  if (!ParseCheckPoint(
          brillo::BlobToString(ledger_signed_proof.checkpoint_note),
          ledger_info, &check_point)) {
    LOG(ERROR) << "Failed to parse checkpoint note.";
    return false;
  }

  // Calculate tree root.
  brillo::Blob calculated_root_hash;
  if (!CalculateRootHash(ledger_signed_proof.logged_record.public_ledger_entry,
                         ledger_signed_proof.inclusion_proof,
                         ledger_signed_proof.logged_record.leaf_index,
                         check_point.size, &calculated_root_hash)) {
    LOG(ERROR) << "Failed to calculate root hash.";
    return false;
  }

  // Verify if the root hash is as expected.
  return calculated_root_hash == check_point.hash;
}

}  // namespace cryptorecovery
}  // namespace cryptohome
