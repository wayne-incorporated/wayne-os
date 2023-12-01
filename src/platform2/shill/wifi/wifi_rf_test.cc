// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi_rf.h"

#include <gtest/gtest.h>

namespace shill {

TEST(WiFiRFTest, WiFiBandName) {
  EXPECT_EQ("2.4GHz", WiFiBandName(WiFiBand::kLowBand));
  EXPECT_EQ("5GHz", WiFiBandName(WiFiBand::kHighBand));
  EXPECT_EQ("all-bands", WiFiBandName(WiFiBand::kAllBands));
  EXPECT_EQ("unknown", WiFiBandName(WiFiBand::kUnknownBand));
}

TEST(WiFiRFTest, WiFiBandFromName) {
  EXPECT_EQ(WiFiBand::kLowBand, WiFiBandFromName("2.4GHz"));
  EXPECT_EQ(WiFiBand::kHighBand, WiFiBandFromName("5GHz"));
  EXPECT_EQ(WiFiBand::kAllBands, WiFiBandFromName("all-bands"));
  EXPECT_EQ(WiFiBand::kUnknownBand, WiFiBandFromName("6GHz"));
  EXPECT_EQ(WiFiBand::kUnknownBand, WiFiBandFromName("unknown"));
  EXPECT_EQ(WiFiBand::kUnknownBand, WiFiBandFromName("foo"));
  EXPECT_EQ(WiFiBand::kUnknownBand, WiFiBandFromName(""));
}

}  // namespace shill
