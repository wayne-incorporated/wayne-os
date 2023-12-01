// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi_state.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using testing::MatchesRegex;
using testing::Test;

namespace shill {
class WiFiStateTest : public ::testing::Test {
 public:
  WiFiStateTest() : wifi_state_() {}
  ~WiFiStateTest() override = default;

 protected:
  WiFiState wifi_state_;
};

TEST_F(WiFiStateTest, SetPhyStateAndEnsuredScanState) {
  // Verify the initial state.
  EXPECT_EQ(wifi_state_.GetEnsuredScanState(),
            WiFiState::EnsuredScanState::kIdle);
  EXPECT_EQ(wifi_state_.GetPhyState(), WiFiState::PhyState::kIdle);
  EXPECT_EQ(wifi_state_.GetScanMethod(), WiFiState::ScanMethod::kNone);
  EXPECT_EQ(wifi_state_.GetEnsuredScanStateString(), "Idle");
  EXPECT_EQ(wifi_state_.GetPhyStateString(), "Idle");
  EXPECT_EQ(wifi_state_.GetScanMethodString(), "None");

  // Set the Phy State to indicate a full scan.
  wifi_state_.SetPhyState(WiFiState::PhyState::kScanning,
                          WiFiState::ScanMethod::kFull);

  // Set the Ensured Scan State to indicate waiting on a scan.
  wifi_state_.SetEnsuredScanState(WiFiState::EnsuredScanState::kWaiting);

  // Verify that the state is as expected.
  EXPECT_EQ(wifi_state_.GetEnsuredScanState(),
            WiFiState::EnsuredScanState::kWaiting);
  EXPECT_EQ(wifi_state_.GetPhyState(), WiFiState::PhyState::kScanning);
  EXPECT_EQ(wifi_state_.GetScanMethod(), WiFiState::ScanMethod::kFull);
  EXPECT_EQ(wifi_state_.GetEnsuredScanStateString(), "Waiting");
  EXPECT_EQ(wifi_state_.GetPhyStateString(), "Scanning");
  EXPECT_EQ(wifi_state_.GetScanMethodString(), "Full");
}
}  // namespace shill
