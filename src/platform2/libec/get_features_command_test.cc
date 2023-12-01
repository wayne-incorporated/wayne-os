// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/get_features_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(GetFeaturesCommand, GetFeaturesCommand) {
  GetFeaturesCommand cmd;
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_GET_FEATURES);
}

// Mock the underlying EcCommand to test.
class GetFeaturesCommandTest : public testing::Test {
 public:
  class MockGetFeaturesCommand : public GetFeaturesCommand {
   public:
    using GetFeaturesCommand::GetFeaturesCommand;
    MOCK_METHOD(const struct ec_response_get_features*,
                Resp,
                (),
                (const, override));
  };
};

TEST_F(GetFeaturesCommandTest, IsFeatureSupported) {
  MockGetFeaturesCommand mock_command;
  struct ec_response_get_features response {};
  response.flags[0] = EC_FEATURE_MASK_0(ec_feature_code::EC_FEATURE_FLASH);
  response.flags[1] = EC_FEATURE_MASK_1(ec_feature_code::EC_FEATURE_EFS2);

  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_TRUE(
      mock_command.IsFeatureSupported(ec_feature_code::EC_FEATURE_FLASH));
  EXPECT_TRUE(
      mock_command.IsFeatureSupported(ec_feature_code::EC_FEATURE_EFS2));
  EXPECT_FALSE(
      mock_command.IsFeatureSupported(ec_feature_code::EC_FEATURE_LED));
  EXPECT_FALSE(
      mock_command.IsFeatureSupported(ec_feature_code::EC_FEATURE_SCP));
}

TEST_F(GetFeaturesCommandTest, IsFeatureSupported_TwoFeatures) {
  MockGetFeaturesCommand mock_command;
  struct ec_response_get_features response {};
  response.flags[0] = EC_FEATURE_MASK_0(ec_feature_code::EC_FEATURE_FLASH) |
                      EC_FEATURE_MASK_0(ec_feature_code::EC_FEATURE_LED);

  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_TRUE(
      mock_command.IsFeatureSupported(ec_feature_code::EC_FEATURE_FLASH));
  EXPECT_TRUE(mock_command.IsFeatureSupported(ec_feature_code::EC_FEATURE_LED));
}

TEST_F(GetFeaturesCommandTest, IsFeatureSupported_FeaturesEqualMod32) {
  MockGetFeaturesCommand mock_command;
  struct ec_response_get_features response {};
  response.flags[0] = EC_FEATURE_MASK_0(ec_feature_code::EC_FEATURE_FLASH);

  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_EQ(ec_feature_code::EC_FEATURE_FLASH, 1);
  EXPECT_EQ(ec_feature_code::EC_FEATURE_HOST_EVENT64, 33);

  EXPECT_TRUE(
      mock_command.IsFeatureSupported(ec_feature_code::EC_FEATURE_FLASH));
  // EC_FEATURE_FLASH = 1 and EC_FEATURE_HOST_EVENT64 = 33. Make sure that the
  // two are not treated the same since (33 % 32) = 1.
  EXPECT_FALSE(mock_command.IsFeatureSupported(
      ec_feature_code::EC_FEATURE_HOST_EVENT64));
}

}  // namespace
}  // namespace ec
