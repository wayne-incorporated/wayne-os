// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_DIGEST_ALGORITHMS_H_
#define LIBHWSEC_BACKEND_DIGEST_ALGORITHMS_H_

#include <brillo/secure_blob.h>
#include <openssl/evp.h>

#include "libhwsec/status.h"

namespace hwsec {

enum class DigestAlgorithm {
  kNoDigest,
  kMd5,
  kSha1,
  kSha224,
  kSha256,
  kSha384,
  kSha512,
  kMaxValue = kSha512,
};

struct ParsedDigestInfo {
  DigestAlgorithm algorithm;
  brillo::Blob blob;
};

inline constexpr size_t GetDigestLength(DigestAlgorithm algo) {
  switch (algo) {
    case DigestAlgorithm::kNoDigest:
      return 0;
    case DigestAlgorithm::kMd5:
      return 16;
    case DigestAlgorithm::kSha1:
      return 20;
    case DigestAlgorithm::kSha224:
      return 28;
    case DigestAlgorithm::kSha256:
      return 32;
    case DigestAlgorithm::kSha384:
      return 48;
    case DigestAlgorithm::kSha512:
      return 64;
  }
}

inline constexpr const EVP_MD* GetOpenSSLDigest(DigestAlgorithm algo) {
  switch (algo) {
    case DigestAlgorithm::kNoDigest:
      return nullptr;
    case DigestAlgorithm::kMd5:
      return EVP_md5();
    case DigestAlgorithm::kSha1:
      return EVP_sha1();
    case DigestAlgorithm::kSha224:
      return EVP_sha224();
    case DigestAlgorithm::kSha256:
      return EVP_sha256();
    case DigestAlgorithm::kSha384:
      return EVP_sha384();
    case DigestAlgorithm::kSha512:
      return EVP_sha512();
  }
}

// Parse the matched digest info from the blob.
std::optional<ParsedDigestInfo> ParseDigestInfo(const brillo::Blob& input);

StatusOr<brillo::Blob> GetDigestAlgorithmEncoding(DigestAlgorithm algo);
StatusOr<brillo::Blob> DigestData(DigestAlgorithm algo, brillo::Blob data);

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_DIGEST_ALGORITHMS_H_
