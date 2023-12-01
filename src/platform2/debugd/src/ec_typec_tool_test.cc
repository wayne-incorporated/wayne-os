// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/ec_typec_tool.h"

#include <gtest/gtest.h>

namespace {
constexpr char kGibberishInput[] =
    "0w934875093485-132085jknl@#$#@$%@!!!\n\\y\\y\\y\f\f\f\t80947350345";
}  // namespace

namespace debugd {

class EcTypeCToolTest : public ::testing::Test {};

TEST_F(EcTypeCToolTest, DpStateTest) {
  brillo::ErrorPtr error;
  EcTypeCTool typec_tool;

  // Check for valid DP cases.
  bool dp;
  auto input = std::string(
      "Port 0: USB=1 DP=1 POLARITY=NORMAL HPD_IRQ=0 HPD_LVL=0 SAFE=0 TBT=0 "
      "USB4=0\n"
      "Port 1: USB=1 DP=0 POLARITY=NORMAL HPD_IRQ=0 HPD_LVL=0 SAFE=0 TBT=0 "
      "USB4=0");
  EXPECT_TRUE(typec_tool.ParseDpState(&error, 0, input, &dp));
  EXPECT_TRUE(dp);
  EXPECT_TRUE(typec_tool.ParseDpState(&error, 1, input, &dp));
  EXPECT_FALSE(dp);
  EXPECT_FALSE(typec_tool.ParseDpState(&error, 2, input, &dp));

  // Check for gibberish invalid input.
  input = std::string(kGibberishInput);
  EXPECT_FALSE(typec_tool.ParseDpState(&error, 0, input, &dp));

  // Check for when the mux state seems right, but is missing DP entries
  // altogether.
  input = std::string(
      "Port 0: USB=1 POLARITY=NORMAL HPD_IRQ=0 HPD_LVL=0 SAFE=0 TBT=0 USB4=0\n"
      "Port 1: USB=1 POLARITY=NORMAL HPD_IRQ=0 HPD_LVL=0 SAFE=0 TBT=0 USB4=0");
  EXPECT_FALSE(typec_tool.ParseDpState(&error, 0, input, &dp));
}

TEST_F(EcTypeCToolTest, HpdStateTest) {
  brillo::ErrorPtr error;
  EcTypeCTool typec_tool;

  // Check for valid HPD cases.
  bool hpd;
  auto input = std::string("GPIO usb_c1_hpd = 0");
  EXPECT_TRUE(typec_tool.ParseHpdState(&error, 1, input, &hpd));
  EXPECT_FALSE(hpd);
  input = std::string("GPIO usb_c1_hpd = 1");
  EXPECT_TRUE(typec_tool.ParseHpdState(&error, 1, input, &hpd));
  EXPECT_TRUE(hpd);

  // Gibberish input.
  input = std::string(kGibberishInput);
  EXPECT_FALSE(typec_tool.ParseHpdState(&error, 1, input, &hpd));

  // More than 1 GPIO returned.
  input = std::string("GPIO usb_c1_hpd = 0\nGPIO usb_cX_hpd = 0");
  EXPECT_FALSE(typec_tool.ParseHpdState(&error, 1, input, &hpd));

  // Differently named GPIO returned.
  input = std::string("GPIO foo = 0");
  EXPECT_FALSE(typec_tool.ParseHpdState(&error, 1, input, &hpd));
}

}  // namespace debugd
