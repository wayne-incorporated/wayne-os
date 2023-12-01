// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <optional>

#include "libec/fingerprint/fp_read_match_secret_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(FpReadMatchSecretCommand, FpReadMatchSecretCommand) {
  FpReadMatchSecretCommand cmd(1);
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_FP_READ_MATCH_SECRET);
  EXPECT_EQ(cmd.Req()->fgr, 1);
}

TEST(FpReadMatchSecretCommand, DestructorClearsBuffer) {
  const std::array<uint8_t, 32> kZeroPositiveMatchSecret{};
  const std::array<uint8_t, 32> kPositiveMatchSecret = {1, 2, 3};

  FpReadMatchSecretCommand cmd(1);

  std::copy(kPositiveMatchSecret.cbegin(), kPositiveMatchSecret.cend(),
            cmd.Resp()->positive_match_secret);
  EXPECT_THAT(cmd.Resp()->positive_match_secret,
              testing::ElementsAreArray(kPositiveMatchSecret));

  // Call destructor without deleting object.
  // Note that the destructor will still be called when the object goes out of
  // scope, so it will be called twice in this test.
  cmd.~FpReadMatchSecretCommand();

  EXPECT_THAT(cmd.Resp()->positive_match_secret,
              testing::ElementsAreArray(kZeroPositiveMatchSecret));
}

// Mock the underlying EcCommand to test.
class FpReadMatchSecretCommandTest : public testing::Test {
 public:
  class MockFpReadMatchSecretCommand : public FpReadMatchSecretCommand {
   public:
    using FpReadMatchSecretCommand::FpReadMatchSecretCommand;
    MOCK_METHOD(struct ec_response_fp_read_match_secret*, Resp, (), (override));
    MOCK_METHOD(bool, EcCommandRun, (int), (override));
  };
};

TEST_F(FpReadMatchSecretCommandTest, Success) {
  MockFpReadMatchSecretCommand mock_command(1);
  struct ec_response_fp_read_match_secret response = {
      .positive_match_secret = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11,
                                12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                                23, 24, 25, 26, 27, 28, 29, 30, 31, 32}};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));
  EXPECT_CALL(mock_command, EcCommandRun).WillRepeatedly(Return(true));

  EXPECT_TRUE(mock_command.Run(-1));

  EXPECT_EQ(mock_command.Secret(),
            brillo::SecureVector({1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11,
                                  12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                                  23, 24, 25, 26, 27, 28, 29, 30, 31, 32}));

  // The second time we read the secret, it should have been cleared, so is no
  // longer valid.
  EXPECT_EQ(mock_command.Secret(), std::nullopt);
}

}  // namespace
}  // namespace ec
