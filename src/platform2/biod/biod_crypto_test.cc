// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include <gtest/gtest.h>

#include "biod/biod_crypto.h"
#include "biod/biod_crypto_test_data.h"

namespace biod {
namespace {

using crypto_test_data::kFakePositiveMatchSecret1;
using crypto_test_data::kFakeValidationValue1;
using crypto_test_data::kUserID;

TEST(BiodCryptoTest, ComputeValidationValue) {
  std::vector<uint8_t> result;
  EXPECT_TRUE(BiodCrypto::ComputeValidationValue(kFakePositiveMatchSecret1,
                                                 kUserID, &result));
  EXPECT_EQ(result, kFakeValidationValue1);
}

TEST(BiodCryptoTest, ComputeValidationValue_InvalidUserId) {
  std::string invalid_user_id = "nothex";
  std::vector<uint8_t> result;
  EXPECT_FALSE(BiodCrypto::ComputeValidationValue(kFakePositiveMatchSecret1,
                                                  invalid_user_id, &result));
  EXPECT_TRUE(result.empty());
}

}  // namespace
}  // namespace biod
