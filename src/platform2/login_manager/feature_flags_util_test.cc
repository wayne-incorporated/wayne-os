// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/feature_flags_util.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "login_manager/feature_flags_tables.h"

namespace login_manager {
namespace {

TEST(MapSwitchToFeatureFlagsTest, MapsSorted) {
  EXPECT_TRUE(std::is_sorted(std::begin(kFeaturesMap), std::end(kFeaturesMap)));
  EXPECT_TRUE(std::is_sorted(std::begin(kSwitchesMap), std::end(kSwitchesMap)));
}

void Check(const std::string& switch_string,
           bool expected_status,
           const std::vector<std::string>& expected_feature_flags) {
  std::vector<std::string> actual_feature_flags;
  bool actual_status =
      MapSwitchToFeatureFlags(switch_string, &actual_feature_flags);
  EXPECT_EQ(std::make_pair(actual_status, actual_feature_flags),
            std::make_pair(expected_status, expected_feature_flags));
}

TEST(MapSwitchToFeatureFlagsTest, Valid) {
  Check("--tint-composited-content", true, {"tint-composited-content"});
  Check("-tint-composited-content", true, {"tint-composited-content"});
  Check("--enable-cros-action-recorder=disable-and-delete-previous-log", true,
        {"enable-cros-action-recorder@4"});
  Check("--enable-features=DarkLightMode", true, {"dark-light-mode@1"});
  Check("--disable-features=DarkLightMode", true, {"dark-light-mode@2"});
  Check("--enable-features=IsolatePrerenders:max_srp_prefetches/-1", true,
        {"enable-google-srp-isolated-prerenders@2"});
  Check("--enable-features=DarkLightMode,TrustTokens", true,
        {"dark-light-mode@1", "trust-tokens@1"});
}

TEST(MapSwitchToFeatureFlagsTest, Invalid) {
  Check("tint-composited-content", false, {});
  Check("--no-such-flag", false, {});
  Check("--enable-features=NonExistingFeature", false, {});
  Check("--disable-features=NonExistingFeature", false, {});
}

}  // namespace
}  // namespace login_manager
