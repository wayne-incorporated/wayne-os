// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include <gtest/gtest.h>

#include <base/strings/string_number_conversions.h>

#include "libec/ec_command.h"
#include "libec/fingerprint/fp_context_command.h"

namespace ec {
namespace {

constexpr int kExpectedUserIdBytes = 32;

TEST(FpContextCommand, FpContextCommand_v0) {
  const std::vector<uint8_t> expected = {0xbe, 0xef};
  auto cmd = FpContextCommand_v0::Create("BEEF");
  EXPECT_TRUE(cmd);
  EXPECT_EQ(cmd->Version(), 0);
  EXPECT_EQ(cmd->Command(), EC_CMD_FP_CONTEXT);
  EXPECT_EQ(memcmp(cmd->Req()->userid, expected.data(), expected.size()), 0);
}

TEST(FpContextCommand, FpContextCommand_v1) {
  const std::vector<uint8_t> expected = {0xbe, 0xef};
  auto cmd = FpContextCommand_v1::Create("BEEF");
  EXPECT_TRUE(cmd);
  EXPECT_EQ(cmd->Version(), 1);
  EXPECT_EQ(cmd->Command(), EC_CMD_FP_CONTEXT);
  EXPECT_EQ(cmd->Req()->action, FP_CONTEXT_ASYNC);
  EXPECT_EQ(memcmp(cmd->Req()->userid, expected.data(), expected.size()), 0);
  EXPECT_EQ(cmd->options().poll_for_result_num_attempts, 70);
  EXPECT_EQ(cmd->options().poll_interval, base::Milliseconds(100));
}

template <typename T>
class FpContextCommandTest : public testing::Test {};
// Run each of the TYPED_TESTs below for the following classes
using CommandTypes = testing::Types<FpContextCommand_v0, FpContextCommand_v1>;
TYPED_TEST_SUITE(FpContextCommandTest, CommandTypes);

TYPED_TEST(FpContextCommandTest, LongHexTruncated) {
  std::string user_hex_too_long =
      "deadbeef"
      "deadbeef"
      "deadbeef"
      "deadbeef"
      "deadbeef"
      "deadbeef"
      "deadbeef"
      "deadbeef"
      "deadbeef";
  // In hex encoding, two characters are needed for each byte.
  ASSERT_EQ(user_hex_too_long.size(), 36 * 2);

  const std::vector<uint8_t> expected = {
      0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe,
      0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
      0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
  };
  ASSERT_EQ(expected.size(), kExpectedUserIdBytes);

  auto cmd = TypeParam::Create(user_hex_too_long);
  EXPECT_TRUE(cmd);
  ASSERT_EQ(sizeof(cmd->Req()->userid), expected.size());
  EXPECT_EQ(memcmp(cmd->Req()->userid, expected.data(), expected.size()), 0);
}

TYPED_TEST(FpContextCommandTest, StringNotHex) {
  std::string not_hex = "BEEFY";
  auto cmd = TypeParam::Create(not_hex);
  EXPECT_FALSE(cmd);
}

TYPED_TEST(FpContextCommandTest, EmptyString) {
  std::string empty;
  const std::vector<uint8_t> zeroes(kExpectedUserIdBytes);
  auto cmd = TypeParam::Create(empty);
  EXPECT_TRUE(cmd);
  ASSERT_EQ(sizeof(cmd->Req()->userid), zeroes.size());
  EXPECT_EQ(memcmp(cmd->Req()->userid, zeroes.data(), zeroes.size()), 0);
}

}  // namespace
}  // namespace ec
