// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <gtest/gtest.h>

#include "cryptohome/auth_factor/auth_factor_label.h"

namespace cryptohome {

TEST(AuthFactorLabelTest, Valid) {
  EXPECT_TRUE(IsValidAuthFactorLabel("foo"));
  EXPECT_TRUE(IsValidAuthFactorLabel("BaR"));
  EXPECT_TRUE(IsValidAuthFactorLabel("123"));
  EXPECT_TRUE(IsValidAuthFactorLabel("foo123"));
  EXPECT_TRUE(IsValidAuthFactorLabel("foo-123"));
  EXPECT_TRUE(IsValidAuthFactorLabel("FOO_123"));
}

TEST(AuthFactorLabelTest, Invalid) {
  EXPECT_FALSE(IsValidAuthFactorLabel(""));
  EXPECT_FALSE(IsValidAuthFactorLabel("."));
  EXPECT_FALSE(IsValidAuthFactorLabel("a.b"));
  EXPECT_FALSE(IsValidAuthFactorLabel("a/b"));
  EXPECT_FALSE(IsValidAuthFactorLabel("a\\b"));
  EXPECT_FALSE(IsValidAuthFactorLabel("a b"));
  EXPECT_FALSE(IsValidAuthFactorLabel(std::string(1, '\0')));
  EXPECT_FALSE(IsValidAuthFactorLabel("\1"));
  EXPECT_FALSE(IsValidAuthFactorLabel("\n"));
  EXPECT_FALSE(IsValidAuthFactorLabel("\xFF"));
  EXPECT_FALSE(IsValidAuthFactorLabel("\xFF"));
  EXPECT_FALSE(IsValidAuthFactorLabel("\U0001f34c"));
}

TEST(AuthFactorLabelTest, ExcessivelyLong) {
  const int kExcessiveLabelLength = 1000 * 1000;
  EXPECT_FALSE(IsValidAuthFactorLabel(std::string(kExcessiveLabelLength, 'a')));
}

}  // namespace cryptohome
