// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libsegmentation/feature_management.h"
#include "libsegmentation/feature_management_fake.h"

#include "proto/feature_management.pb.h"

namespace segmentation {

using chromiumos::feature_management::api::software::Feature;
using ::testing::Return;

class FeatureManagementTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto fake = std::make_unique<fake::FeatureManagementFake>();
    fake_ = fake.get();
    feature_management_ = std::make_unique<FeatureManagement>(std::move(fake));
  }

  std::unique_ptr<FeatureManagement> feature_management_;
  fake::FeatureManagementFake* fake_;
};

TEST_F(FeatureManagementTest, GetInterface) {
  using chromiumos::feature_management::api::software::Feature;
  // Be sure the copied interface matches the protobuffer.
  EXPECT_EQ(USAGE_LOCAL, Feature::USAGE_LOCAL);
  EXPECT_EQ(USAGE_CHROME, Feature::USAGE_CHROME);
  EXPECT_EQ(USAGE_ANDROID, Feature::USAGE_ANDROID);
}

TEST_F(FeatureManagementTest, GetFeature) {
  fake_->SetFeature("my_feature", USAGE_LOCAL);
  EXPECT_EQ(feature_management_->IsFeatureEnabled("my_feature"), true);
}

TEST_F(FeatureManagementTest, GetFeatureDoesNotExist) {
  EXPECT_EQ(feature_management_->IsFeatureEnabled("fake"), false);
}

TEST_F(FeatureManagementTest, GetFeatureLevel) {
  EXPECT_EQ(feature_management_->GetFeatureLevel(), 0);
  fake_->SetFeatureLevel(
      FeatureManagementInterface::FeatureLevel::FEATURE_LEVEL_1);
  EXPECT_EQ(feature_management_->GetFeatureLevel(), 1);
}

TEST_F(FeatureManagementTest, ListFeatures) {
  fake_->SetFeature("my_feature", USAGE_LOCAL);
  fake_->SetFeature("my_other_feature", USAGE_LOCAL);

  std::set<std::string> features =
      feature_management_->ListFeatures(USAGE_LOCAL);
  EXPECT_EQ(features.size(), 2);
  EXPECT_NE(features.find("my_feature"), features.end());
  EXPECT_NE(features.find("my_other_feature"), features.end());

  features = feature_management_->ListFeatures(USAGE_ANDROID);
  EXPECT_EQ(features.size(), 0);
}
}  // namespace segmentation
