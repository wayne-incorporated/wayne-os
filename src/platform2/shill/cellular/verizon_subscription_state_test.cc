// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/verizon_subscription_state.h"

#include <memory>
#include <tuple>
#include <vector>

#include <gtest/gtest.h>

namespace shill {

class VerizonSubscriptionStateInvalidPcoTest
    : public testing::TestWithParam<std::vector<uint8_t>> {};

TEST_P(VerizonSubscriptionStateInvalidPcoTest,
       FindVerizonSubscriptionStateFromPco) {
  const auto& raw_data = GetParam();
  std::unique_ptr<CellularPco> pco = CellularPco::CreateFromRawData(raw_data);
  ASSERT_NE(nullptr, pco);
  SubscriptionState subscription_state = SubscriptionState::kUnknown;
  EXPECT_FALSE(FindVerizonSubscriptionStateFromPco(*pco, &subscription_state));
  EXPECT_EQ(SubscriptionState::kUnknown, subscription_state);
}

INSTANTIATE_TEST_SUITE_P(
    VerizonSubscriptionStateInvalidPcoTest,
    VerizonSubscriptionStateInvalidPcoTest,
    testing::Values(
        // Verizon-specific PCO not found
        std::vector<uint8_t>({0x27, 0x04, 0x00, 0xAA, 0xBB, 0x00}),
        // Malformed Verizon-specific PCO
        std::vector<uint8_t>({0x27, 0x04, 0x00, 0xFF, 0x00, 0x00}),
        std::vector<uint8_t>({0x27, 0x07, 0x00, 0xFF, 0x00, 0x03, 0x13, 0x01,
                              0x84}),
        std::vector<uint8_t>({0x27, 0x08, 0x00, 0xFF, 0x00, 0x04, 0xEE, 0x01,
                              0x84, 0x00}),
        std::vector<uint8_t>({0x27, 0x08, 0x00, 0xFF, 0x00, 0x04, 0x13, 0xEE,
                              0x84, 0x00}),
        std::vector<uint8_t>({0x27, 0x08, 0x00, 0xFF, 0x00, 0x04, 0x13, 0x01,
                              0xEE, 0x00}),
        std::vector<uint8_t>({
            // clang-format off
            0x27, 0x09, 0x00, 0xFF, 0x00, 0x05, 0x13, 0x01, 0xEE, 0x00, 0x00
            // clang-format on
        })));

using VerizonSubscriptionStateTestParams =
    std::tuple<std::vector<uint8_t>,  // raw data
               SubscriptionState>;    // expected subscription state

class VerizonSubscriptionStateTest
    : public testing::TestWithParam<VerizonSubscriptionStateTestParams> {};

TEST_P(VerizonSubscriptionStateTest, FindVerizonSubscriptionStateFromPco) {
  const auto& raw_data = std::get<0>(GetParam());
  SubscriptionState expected_subscription_state = std::get<1>(GetParam());
  std::unique_ptr<CellularPco> pco = CellularPco::CreateFromRawData(raw_data);
  ASSERT_NE(nullptr, pco);
  SubscriptionState subscription_state = SubscriptionState::kUnknown;
  EXPECT_TRUE(FindVerizonSubscriptionStateFromPco(*pco, &subscription_state));
  EXPECT_EQ(expected_subscription_state, subscription_state);
}

INSTANTIATE_TEST_SUITE_P(
    VerizonSubscriptionStateTest,
    VerizonSubscriptionStateTest,
    testing::Values(
        std::make_tuple(std::vector<uint8_t>({0x27, 0x08, 0x00, 0xFF, 0x00,
                                              0x04, 0x13, 0x01, 0x84, 0x00}),
                        SubscriptionState::kProvisioned),
        std::make_tuple(std::vector<uint8_t>({0x27, 0x08, 0x00, 0xFF, 0x00,
                                              0x04, 0x13, 0x01, 0x84, 0x03}),
                        SubscriptionState::kOutOfCredits),
        std::make_tuple(std::vector<uint8_t>({0x27, 0x08, 0x00, 0xFF, 0x00,
                                              0x04, 0x13, 0x01, 0x84, 0x05}),
                        SubscriptionState::kUnprovisioned),
        std::make_tuple(std::vector<uint8_t>({0x27, 0x08, 0x00, 0xFF, 0x00,
                                              0x04, 0x13, 0x01, 0x84, 0xFF}),
                        SubscriptionState::kUnknown)));

}  // namespace shill
