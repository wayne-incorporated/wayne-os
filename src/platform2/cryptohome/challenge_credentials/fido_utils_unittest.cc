// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/challenge_credentials/fido_utils.h"

#include <vector>

#include <gtest/gtest.h>

#include "brillo/secure_blob.h"

namespace cryptohome {

TEST(FidoUtilsTest, GetFidoUserIdTest) {
  std::string user_id{"test_id"};
  auto digest = GetFidoUserId(user_id);

  std::string expected_id{
      "0fb27832c685c35889ba3653994bae061237518c40ed57d3b41eae17bf923137"};
  brillo::SecureBlob blob;
  ASSERT_TRUE(brillo::SecureBlob::HexStringToSecureBlob(expected_id, &blob));
  std::vector<uint8_t> expected(blob.begin(), blob.end());
  EXPECT_EQ(digest, expected);
}

}  // namespace cryptohome
