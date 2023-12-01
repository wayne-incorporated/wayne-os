// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/digest_algorithms.h"

#include <algorithm>
#include <optional>
#include <string>

#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/evp.h>

#include "libhwsec/status.h"

using hwsec_foundation::status::MakeStatus;

namespace hwsec {

namespace {

// The DER encoding of MD5 DigestInfo as defined in PKCS #1.
constexpr uint8_t kMd5DigestInfo[] = {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08,
                                      0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                      0x02, 0x05, 0x05, 0x00, 0x04, 0x10};

// The DER encoding of SHA-1 DigestInfo as defined in PKCS #1.
constexpr uint8_t kSha1DigestInfo[] = {0x30, 0x21, 0x30, 0x09, 0x06,
                                       0x05, 0x2b, 0x0e, 0x03, 0x02,
                                       0x1a, 0x05, 0x00, 0x04, 0x14};

// The DER encoding of SHA-256 DigestInfo as defined in PKCS #1.
constexpr uint8_t kSha256DigestInfo[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

// The DER encoding of SHA-384 DigestInfo as defined in PKCS #1.
constexpr uint8_t kSha384DigestInfo[] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};

// The DER encoding of SHA-512 DigestInfo as defined in PKCS #1.
constexpr uint8_t kSha512DigestInfo[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

// Empty digset info.
constexpr uint8_t kNoDigestInfo[] = {};

constexpr struct {
  DigestAlgorithm algorithm;
  const uint8_t* digest_info;
  size_t len;
} kDigestInfos[] = {
    {
        .algorithm = DigestAlgorithm::kNoDigest,
        .digest_info = kNoDigestInfo,
        .len = sizeof(kNoDigestInfo),
    },
    {
        .algorithm = DigestAlgorithm::kMd5,
        .digest_info = kMd5DigestInfo,
        .len = sizeof(kMd5DigestInfo),
    },
    {
        .algorithm = DigestAlgorithm::kSha1,
        .digest_info = kSha1DigestInfo,
        .len = sizeof(kSha1DigestInfo),
    },
    {
        .algorithm = DigestAlgorithm::kSha256,
        .digest_info = kSha256DigestInfo,
        .len = sizeof(kSha256DigestInfo),
    },
    {
        .algorithm = DigestAlgorithm::kSha384,
        .digest_info = kSha384DigestInfo,
        .len = sizeof(kSha384DigestInfo),
    },
    {
        .algorithm = DigestAlgorithm::kSha512,
        .digest_info = kSha512DigestInfo,
        .len = sizeof(kSha512DigestInfo),
    },
};

}  // namespace

std::optional<ParsedDigestInfo> ParseDigestInfo(const brillo::Blob& input) {
  for (const auto& info : kDigestInfos) {
    if (input.size() == GetDigestLength(info.algorithm) + info.len) {
      if (std::equal(info.digest_info, info.digest_info + info.len,
                     input.begin())) {
        return ParsedDigestInfo{
            .algorithm = info.algorithm,
            .blob = brillo::Blob(input.begin() + info.len, input.end()),
        };
      }
    }
  }
  return std::nullopt;
}

StatusOr<brillo::Blob> GetDigestAlgorithmEncoding(DigestAlgorithm algo) {
  for (const auto& info : kDigestInfos) {
    if (info.algorithm == algo) {
      return brillo::Blob(info.digest_info, info.digest_info + info.len);
    }
  }
  return MakeStatus<TPMError>("Unsupported digest info",
                              TPMRetryAction::kNoRetry);
}

StatusOr<brillo::Blob> DigestData(DigestAlgorithm algo, brillo::Blob data) {
  const EVP_MD* digest_type = GetOpenSSLDigest(algo);
  if (digest_type == nullptr) {
    return data;
  }

  brillo::Blob result(EVP_MD_size(digest_type));
  unsigned int result_size = 0;

  crypto::ScopedEVP_MD_CTX ctx(EVP_MD_CTX_new());

  if (!EVP_DigestInit(ctx.get(), digest_type)) {
    return MakeStatus<TPMError>("EVP_DigestInit failed",
                                TPMRetryAction::kNoRetry);
  }

  if (!EVP_DigestUpdate(ctx.get(), data.data(), data.size())) {
    return MakeStatus<TPMError>("EVP_DigestUpdate failed",
                                TPMRetryAction::kNoRetry);
  }

  if (!EVP_DigestFinal(ctx.get(), result.data(), &result_size)) {
    return MakeStatus<TPMError>("EVP_DigestUpdate failed",
                                TPMRetryAction::kNoRetry);
  }

  if (result_size != result.size()) {
    return MakeStatus<TPMError>("Digest result size mismatch",
                                TPMRetryAction::kNoRetry);
  }

  return result;
}

}  // namespace hwsec
