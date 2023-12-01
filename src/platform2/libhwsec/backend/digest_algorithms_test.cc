// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/digest_algorithms.h"

#include <memory>
#include <utility>

#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <openssl/sha.h>

#include "libhwsec/status.h"

using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::IsOkAndHolds;
using hwsec_foundation::error::testing::NotOkWith;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnValue;
using testing::_;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;

namespace hwsec {

namespace {
DigestAlgorithm kAllDigestAlgorithms[] = {
    DigestAlgorithm::kNoDigest, DigestAlgorithm::kMd5,
    DigestAlgorithm::kSha1,     DigestAlgorithm::kSha224,
    DigestAlgorithm::kSha256,   DigestAlgorithm::kSha384,
    DigestAlgorithm::kSha512,
};
DigestAlgorithm kCommonDigestAlgorithms[] = {
    DigestAlgorithm::kMd5,    DigestAlgorithm::kSha1,
    DigestAlgorithm::kSha224, DigestAlgorithm::kSha256,
    DigestAlgorithm::kSha384, DigestAlgorithm::kSha512,
};

DigestAlgorithm kSupportedDigestInfoAlgorithms[] = {
    DigestAlgorithm::kMd5,    DigestAlgorithm::kSha1,
    DigestAlgorithm::kSha256, DigestAlgorithm::kSha384,
    DigestAlgorithm::kSha512,
};
}  // namespace

using DigestAlgorithmsTest = ::testing::Test;

TEST_F(DigestAlgorithmsTest, GetDigestLength) {
  EXPECT_EQ(GetDigestLength(DigestAlgorithm::kNoDigest), 0);

  for (auto algo : kCommonDigestAlgorithms) {
    EXPECT_GT(GetDigestLength(algo), 0);
  }
}

TEST_F(DigestAlgorithmsTest, GetOpenSSLDigest) {
  EXPECT_EQ(GetOpenSSLDigest(DigestAlgorithm::kNoDigest), nullptr);

  for (auto algo : kCommonDigestAlgorithms) {
    EXPECT_NE(GetOpenSSLDigest(algo), nullptr);
  }
}

TEST_F(DigestAlgorithmsTest, GetDigestAlgorithmEncoding) {
  EXPECT_THAT(GetDigestAlgorithmEncoding(DigestAlgorithm::kNoDigest),
              IsOkAndHolds(brillo::Blob()));

  EXPECT_THAT(GetDigestAlgorithmEncoding(DigestAlgorithm::kSha224),
              NotOkWith("Unsupported"));

  for (auto algo : kSupportedDigestInfoAlgorithms) {
    auto result = GetDigestAlgorithmEncoding(algo);
    ASSERT_OK(result);
    EXPECT_FALSE(result->empty());
  }
}

TEST_F(DigestAlgorithmsTest, DigestData) {
  for (auto algo : kAllDigestAlgorithms) {
    auto result = DigestData(algo, brillo::Blob());
    ASSERT_OK(result);
    EXPECT_EQ(result->size(), GetDigestLength(algo));
  }
}

}  // namespace hwsec
