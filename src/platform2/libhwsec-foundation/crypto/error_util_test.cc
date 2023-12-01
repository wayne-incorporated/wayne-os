// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/crypto/error_util.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/bnerr.h>
#include <openssl/err.h>

namespace hwsec_foundation {

TEST(ErrorUtilTest, ErrorQueue) {
  EXPECT_TRUE(GetOpenSSLErrors().empty());

  // Trigger 2 different errors to get more interesting OpenSSL error queue.
  ERR_PUT_error(ERR_LIB_BN, 0, BN_R_INPUT_NOT_REDUCED, "", 0);
  ERR_PUT_error(ERR_LIB_BN, 0, BN_R_DIV_BY_ZERO, "", 0);
  EXPECT_THAT(GetOpenSSLErrors(), testing::ContainsRegex(".*;.*;"));

  EXPECT_TRUE(GetOpenSSLErrors().empty());
}

}  // namespace hwsec_foundation
