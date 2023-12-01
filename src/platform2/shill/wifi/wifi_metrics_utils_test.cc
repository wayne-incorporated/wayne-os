// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi_metrics_utils.h"

#include <vector>

#include <gtest/gtest.h>

#include "shill/metrics.h"

namespace shill {

TEST(WiFiMetricsUtilsTest, CanNotReportDisallowedOUI) {
  // It is possible in theory that at some point the hardcoded OUI 12:34:56
  // will be in the OUI allowlist. If that ever happens, it would be fine to
  // change this test OUI with another one that is not expected to be included
  // in the list of acceptable OUIs.
  EXPECT_FALSE(WiFiMetricsUtils::CanReportOUI(0x123456));
}

TEST(WiFiMetricsUtilsTest, CanReportAllowlistedOUI) {
  EXPECT_TRUE(WiFiMetricsUtils::CanReportOUI(
      WiFiMetricsUtils::AllowlistedOUIForTesting()));
}

TEST(WiFiMetricsUtilsTest, CanReportAdapterAX211) {
  EXPECT_TRUE(WiFiMetricsUtils::CanReportAdapterInfo(
      Metrics::WiFiAdapterInfo{0x8086, 0x51f0, 0x0090}));
}

TEST(WiFiMetricsUtilsTest, CanReportAdapterMT7921SDIO) {
  EXPECT_TRUE(WiFiMetricsUtils::CanReportAdapterInfo(
      Metrics::WiFiAdapterInfo{0x037a, 0x7901, -1}));
}

TEST(WiFiMetricsUtilsTest, CanNotReportAdapterMAX3) {
  // That device is not a network adapter, won't ever be in the allowlist.
  EXPECT_FALSE(WiFiMetricsUtils::CanReportAdapterInfo(
      Metrics::WiFiAdapterInfo{0x1bbf, 0x0003, -1}));
}

TEST(WiFiMetricsUtilsTest, BTProfileConversion) {
  std::vector<enum Metrics::BTProfileConnectionState> converted{
      WiFiMetricsUtils::ConvertBTProfileConnectionState(
          BluetoothManagerInterface::BTProfileConnectionState::kDisconnected),
      WiFiMetricsUtils::ConvertBTProfileConnectionState(
          BluetoothManagerInterface::BTProfileConnectionState::kDisconnecting),
      WiFiMetricsUtils::ConvertBTProfileConnectionState(
          BluetoothManagerInterface::BTProfileConnectionState::kConnecting),
      WiFiMetricsUtils::ConvertBTProfileConnectionState(
          BluetoothManagerInterface::BTProfileConnectionState::kConnected),
      WiFiMetricsUtils::ConvertBTProfileConnectionState(
          BluetoothManagerInterface::BTProfileConnectionState::kActive),
      WiFiMetricsUtils::ConvertBTProfileConnectionState(
          BluetoothManagerInterface::BTProfileConnectionState::kInvalid),
  };
  std::vector<enum Metrics::BTProfileConnectionState> expected{
      Metrics::kBTProfileConnectionStateDisconnected,
      Metrics::kBTProfileConnectionStateDisconnecting,
      Metrics::kBTProfileConnectionStateConnecting,
      Metrics::kBTProfileConnectionStateConnected,
      Metrics::kBTProfileConnectionStateActive,
      Metrics::kBTProfileConnectionStateInvalid};
  EXPECT_EQ(converted, expected);
}

}  // namespace shill
