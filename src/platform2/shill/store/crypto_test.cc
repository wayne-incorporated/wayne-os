// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/store/crypto.h"

#include <string>

#include <gtest/gtest.h>

using testing::Test;

namespace shill {

namespace {
const char kPlainText[] = "This is a test!";
const char kROT47Text[] = "rot47:%9:D :D 2 E6DEP";
}  // namespace

TEST(CryptoTest, DecryptNonROT47Fails) {
  EXPECT_FALSE(Crypto::Decrypt(kPlainText));
  EXPECT_FALSE(Crypto::Decrypt(""));
}

TEST(CryptoTest, DecryptROT47Succeeds) {
  EXPECT_EQ(kPlainText, Crypto::Decrypt(kROT47Text));
}

}  // namespace shill
