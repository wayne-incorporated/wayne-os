// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi_link_statistics.h"

#include <algorithm>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>

#include <base/strings/stringprintf.h>

#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>
#include "shill/metrics.h"
#include "shill/mock_log.h"
#include "shill/supplicant/wpa_supplicant.h"

using ::testing::_;
using ::testing::HasSubstr;
using ::testing::Mock;
using ::testing::StrEq;

namespace shill {
namespace {

constexpr WiFiLinkStatistics::StationStats kDhcpStartNl80211Stats = {
    .tx_retries = 5,
    .tx_failed = 9,
    .rx_drop_misc = 15,
    .signal = -33,
    .signal_avg = -30,
    .rx = {.packets = 63, .bytes = 503},
    .tx = {.packets = 75, .bytes = 653}};
constexpr WiFiLinkStatistics::StationStats kDhcpEndNl80211Stats = {
    .tx_retries = 93,
    .tx_failed = 67,
    .rx_drop_misc = 153,
    .signal = -23,
    .signal_avg = -30,
    .rx = {.packets = 3587, .bytes = 52305},
    .tx = {.packets = 4163, .bytes = 56778}};
constexpr WiFiLinkStatistics::StationStats kDhcpDiffNl80211Stats = {
    .tx_retries = 88,
    .tx_failed = 58,
    .rx_drop_misc = 138,
    .signal = -23,
    .signal_avg = -30,
    .rx = {.packets = 3524, .bytes = 51802},
    .tx = {.packets = 4088, .bytes = 56125}};
constexpr WiFiLinkStatistics::StationStats kNetworkValidationStartNl80211Stats =
    {.tx_retries = 20,
     .tx_failed = 15,
     .rx_drop_misc = 37,
     .signal = -28,
     .signal_avg = -29,
     .rx = {.packets = 96, .bytes = 730},
     .tx = {.packets = 112, .bytes = 816}};
constexpr WiFiLinkStatistics::StationStats kNetworkValidationEndNl80211Stats = {
    .tx_retries = 88,
    .tx_failed = 56,
    .rx_drop_misc = 103,
    .signal = -27,
    .signal_avg = -30,
    .rx = {.packets = 3157, .bytes = 29676},
    .tx = {.packets = 3682, .bytes = 31233}};
constexpr WiFiLinkStatistics::StationStats kNetworkValidationDiffNl80211Stats =
    {.tx_retries = 68,
     .tx_failed = 41,
     .rx_drop_misc = 66,
     .signal = -27,
     .signal_avg = -30,
     .rx = {.packets = 3061, .bytes = 28946},
     .tx = {.packets = 3570, .bytes = 30417}};
constexpr old_rtnl_link_stats64 kDhcpStartRtnlStats = {
    17, 32, 105, 206, 3, 2, 8, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
constexpr old_rtnl_link_stats64 kDhcpEndRtnlStats = {
    3862, 3362, 49510, 43641, 35, 31, 29, 55, 0, 0, 0, 0,
    0,    0,    0,     0,     0,  0,  0,  0,  0, 0, 0};
constexpr old_rtnl_link_stats64 kDhcpDiffRtnlStats = {
    3845, 3330, 49405, 43435, 32, 29, 21, 49, 0, 0, 0, 0,
    0,    0,    0,     0,     0,  0,  0,  0,  0, 0, 0};
constexpr old_rtnl_link_stats64 kNetworkValidationStartRtnlStats = {
    29, 36, 278, 233, 6, 3, 11, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
constexpr old_rtnl_link_stats64 kNetworkValidationEndRtnlStats = {
    1509, 2022, 23890, 36217, 21, 26, 23, 31, 0, 0, 0, 0,
    0,    0,    0,     0,     0,  0,  0,  0,  0, 0, 0};
constexpr old_rtnl_link_stats64 kNetworkValidationDiffRtnlStats = {
    1480, 1986, 23612, 35984, 15, 23, 12, 22, 0, 0, 0, 0,
    0,    0,    0,     0,     0,  0,  0,  0,  0, 0, 0};

std::string Nl80211Log(WiFiLinkStatistics::Trigger start_event,
                       WiFiLinkStatistics::Trigger end_event,
                       const WiFiLinkStatistics::StationStats& diff_stats) {
  return "Network event related to NL80211 link statistics: " +
         WiFiLinkStatistics::LinkStatisticsTriggerToString(start_event) +
         " -> " + WiFiLinkStatistics::LinkStatisticsTriggerToString(end_event) +
         "; the NL80211 link statistics delta for the last 0 seconds is " +
         std::string(kPacketReceiveSuccessesProperty) + " " +
         std::to_string(diff_stats.rx.packets) + " " +
         kPacketTransmitSuccessesProperty + " " +
         std::to_string(diff_stats.tx.packets) + " " +
         kByteReceiveSuccessesProperty + " " +
         std::to_string(diff_stats.rx.bytes) + " " +
         kByteTransmitSuccessesProperty + " " +
         std::to_string(diff_stats.tx.bytes) + " " +
         kPacketTransmitFailuresProperty + " " +
         std::to_string(diff_stats.tx_failed) + " " + kTransmitRetriesProperty +
         " " + std::to_string(diff_stats.tx_retries) + " " +
         kPacketReceiveDropProperty + " " +
         std::to_string(diff_stats.rx_drop_misc) +
         "; the current signal information: " + kLastReceiveSignalDbmProperty +
         " " + std::to_string(diff_stats.signal) + " " +
         kAverageReceiveSignalDbmProperty + " " +
         std::to_string(diff_stats.signal_avg);
}

std::string RtnlLog(WiFiLinkStatistics::Trigger start_event,
                    WiFiLinkStatistics::Trigger end_event,
                    const old_rtnl_link_stats64& diff_stats) {
  return "Network event related to RTNL link statistics: " +
         WiFiLinkStatistics::LinkStatisticsTriggerToString(start_event) +
         " -> " + WiFiLinkStatistics::LinkStatisticsTriggerToString(end_event) +
         "; the RTNL link statistics delta for the last 0 seconds is " +
         "rx_packets " + std::to_string(diff_stats.rx_packets) +
         " tx_packets " + std::to_string(diff_stats.tx_packets) + " rx_bytes " +
         std::to_string(diff_stats.rx_bytes) + " tx_bytes " +
         std::to_string(diff_stats.tx_bytes) + " rx_errors " +
         std::to_string(diff_stats.rx_errors) + " tx_errors " +
         std::to_string(diff_stats.tx_errors) + " rx_dropped " +
         std::to_string(diff_stats.rx_dropped) + " tx_dropped " +
         std::to_string(diff_stats.tx_dropped);
}
}  // namespace

class WiFiLinkStatisticsTest : public ::testing::Test {
 public:
  WiFiLinkStatisticsTest() : wifi_link_statistics_(new WiFiLinkStatistics()) {}
  ~WiFiLinkStatisticsTest() override = default;

 protected:
  void UpdateNl80211LinkStatistics(
      WiFiLinkStatistics::Trigger trigger,
      const WiFiLinkStatistics::StationStats& stats) {
    wifi_link_statistics_->UpdateNl80211LinkStatistics(trigger, stats);
  }

  void UpdateRtnlLinkStatistics(WiFiLinkStatistics::Trigger trigger,
                                const old_rtnl_link_stats64& stats) {
    wifi_link_statistics_->UpdateRtnlLinkStatistics(trigger, stats);
  }

 private:
  std::unique_ptr<WiFiLinkStatistics> wifi_link_statistics_;
};

TEST_F(WiFiLinkStatisticsTest, StartEvents) {
  ScopedMockLog log;

  //   Shill should not print link statistics logs at start network events
  EXPECT_CALL(
      log, Log(logging::LOGGING_INFO, _, HasSubstr("NL80211 link statistics")))
      .Times(0);
  EXPECT_CALL(log,
              Log(logging::LOGGING_INFO, _, HasSubstr("RTNL link statistics")))
      .Times(0);

  UpdateNl80211LinkStatistics(
      WiFiLinkStatistics::Trigger::kIPConfigurationStart,
      kDhcpStartNl80211Stats);
  UpdateRtnlLinkStatistics(WiFiLinkStatistics::Trigger::kIPConfigurationStart,
                           kDhcpStartRtnlStats);
  UpdateNl80211LinkStatistics(
      WiFiLinkStatistics::Trigger::kNetworkValidationStart,
      kNetworkValidationStartNl80211Stats);
  UpdateRtnlLinkStatistics(WiFiLinkStatistics::Trigger::kNetworkValidationStart,
                           kNetworkValidationStartRtnlStats);
}

TEST_F(WiFiLinkStatisticsTest, DhcpFailure) {
  ScopedMockLog log;

  EXPECT_CALL(
      log,
      Log(logging::LOGGING_INFO, _,
          StrEq(Nl80211Log(WiFiLinkStatistics::Trigger::kIPConfigurationStart,
                           WiFiLinkStatistics::Trigger::kDHCPFailure,
                           kDhcpDiffNl80211Stats))))
      .Times(1);
  EXPECT_CALL(
      log, Log(logging::LOGGING_INFO, _,
               StrEq(RtnlLog(WiFiLinkStatistics::Trigger::kIPConfigurationStart,
                             WiFiLinkStatistics::Trigger::kDHCPFailure,
                             kDhcpDiffRtnlStats))))
      .Times(1);

  UpdateNl80211LinkStatistics(
      WiFiLinkStatistics::Trigger::kIPConfigurationStart,
      kDhcpStartNl80211Stats);
  UpdateRtnlLinkStatistics(WiFiLinkStatistics::Trigger::kIPConfigurationStart,
                           kDhcpStartRtnlStats);
  UpdateNl80211LinkStatistics(WiFiLinkStatistics::Trigger::kDHCPFailure,
                              kDhcpEndNl80211Stats);
  UpdateRtnlLinkStatistics(WiFiLinkStatistics::Trigger::kDHCPFailure,
                           kDhcpEndRtnlStats);
}

TEST_F(WiFiLinkStatisticsTest, NetworkValidationFailure) {
  ScopedMockLog log;

  EXPECT_CALL(log,
              Log(logging::LOGGING_INFO, _,
                  StrEq(Nl80211Log(
                      WiFiLinkStatistics::Trigger::kNetworkValidationStart,
                      WiFiLinkStatistics::Trigger::kNetworkValidationFailure,
                      kNetworkValidationDiffNl80211Stats))))
      .Times(1);
  EXPECT_CALL(
      log,
      Log(logging::LOGGING_INFO, _,
          StrEq(RtnlLog(WiFiLinkStatistics::Trigger::kNetworkValidationStart,
                        WiFiLinkStatistics::Trigger::kNetworkValidationFailure,
                        kNetworkValidationDiffRtnlStats))))
      .Times(1);

  UpdateNl80211LinkStatistics(
      WiFiLinkStatistics::Trigger::kNetworkValidationStart,
      kNetworkValidationStartNl80211Stats);
  UpdateRtnlLinkStatistics(WiFiLinkStatistics::Trigger::kNetworkValidationStart,
                           kNetworkValidationStartRtnlStats);
  UpdateNl80211LinkStatistics(
      WiFiLinkStatistics::Trigger::kNetworkValidationFailure,
      kNetworkValidationEndNl80211Stats);
  UpdateRtnlLinkStatistics(
      WiFiLinkStatistics::Trigger::kNetworkValidationFailure,
      kNetworkValidationEndRtnlStats);
}

TEST_F(WiFiLinkStatisticsTest, DhcpNetworkValidationFailures) {
  ScopedMockLog log;

  //   Failure event should match the start event of the same type
  EXPECT_CALL(log,
              Log(logging::LOGGING_INFO, _,
                  StrEq(Nl80211Log(
                      WiFiLinkStatistics::Trigger::kNetworkValidationStart,
                      WiFiLinkStatistics::Trigger::kNetworkValidationFailure,
                      kNetworkValidationDiffNl80211Stats))))
      .Times(1);
  EXPECT_CALL(
      log,
      Log(logging::LOGGING_INFO, _,
          StrEq(RtnlLog(WiFiLinkStatistics::Trigger::kNetworkValidationStart,
                        WiFiLinkStatistics::Trigger::kNetworkValidationFailure,
                        kNetworkValidationDiffRtnlStats))))
      .Times(1);
  EXPECT_CALL(
      log,
      Log(logging::LOGGING_INFO, _,
          StrEq(Nl80211Log(WiFiLinkStatistics::Trigger::kIPConfigurationStart,
                           WiFiLinkStatistics::Trigger::kDHCPFailure,
                           kDhcpDiffNl80211Stats))))
      .Times(1);
  EXPECT_CALL(
      log, Log(logging::LOGGING_INFO, _,
               StrEq(RtnlLog(WiFiLinkStatistics::Trigger::kIPConfigurationStart,
                             WiFiLinkStatistics::Trigger::kDHCPFailure,
                             kDhcpDiffRtnlStats))))
      .Times(1);

  UpdateNl80211LinkStatistics(
      WiFiLinkStatistics::Trigger::kIPConfigurationStart,
      kDhcpStartNl80211Stats);
  UpdateRtnlLinkStatistics(WiFiLinkStatistics::Trigger::kIPConfigurationStart,
                           kDhcpStartRtnlStats);
  UpdateNl80211LinkStatistics(
      WiFiLinkStatistics::Trigger::kNetworkValidationStart,
      kNetworkValidationStartNl80211Stats);
  UpdateRtnlLinkStatistics(WiFiLinkStatistics::Trigger::kNetworkValidationStart,
                           kNetworkValidationStartRtnlStats);
  UpdateNl80211LinkStatistics(
      WiFiLinkStatistics::Trigger::kNetworkValidationFailure,
      kNetworkValidationEndNl80211Stats);
  UpdateRtnlLinkStatistics(
      WiFiLinkStatistics::Trigger::kNetworkValidationFailure,
      kNetworkValidationEndRtnlStats);
  UpdateNl80211LinkStatistics(WiFiLinkStatistics::Trigger::kDHCPFailure,
                              kDhcpEndNl80211Stats);
  UpdateRtnlLinkStatistics(WiFiLinkStatistics::Trigger::kDHCPFailure,
                           kDhcpEndRtnlStats);
}

TEST_F(WiFiLinkStatisticsTest, StationInfoTriggerConvert) {
  std::vector<WiFiLinkStatistics::Trigger> triggers = {
      WiFiLinkStatistics::Trigger::kUnknown,
      WiFiLinkStatistics::Trigger::kIPConfigurationStart,
      WiFiLinkStatistics::Trigger::kConnected,
      WiFiLinkStatistics::Trigger::kDHCPRenewOnRoam,
      WiFiLinkStatistics::Trigger::kDHCPSuccess,
      WiFiLinkStatistics::Trigger::kDHCPFailure,
      WiFiLinkStatistics::Trigger::kSlaacFinished,
      WiFiLinkStatistics::Trigger::kNetworkValidationStart,
      WiFiLinkStatistics::Trigger::kNetworkValidationSuccess,
      WiFiLinkStatistics::Trigger::kNetworkValidationFailure,
      WiFiLinkStatistics::Trigger::kCQMRSSILow,
      WiFiLinkStatistics::Trigger::kCQMRSSIHigh,
      WiFiLinkStatistics::Trigger::kCQMBeaconLoss,
      WiFiLinkStatistics::Trigger::kCQMPacketLoss,
      WiFiLinkStatistics::Trigger::kBackground};

  std::vector<Metrics::WiFiLinkQualityTrigger> expected = {
      Metrics::kWiFiLinkQualityTriggerUnknown,
      Metrics::kWiFiLinkQualityTriggerIPConfigurationStart,
      Metrics::kWiFiLinkQualityTriggerConnected,
      Metrics::kWiFiLinkQualityTriggerDHCPRenewOnRoam,
      Metrics::kWiFiLinkQualityTriggerDHCPSuccess,
      Metrics::kWiFiLinkQualityTriggerDHCPFailure,
      Metrics::kWiFiLinkQualityTriggerSlaacFinished,
      Metrics::kWiFiLinkQualityTriggerNetworkValidationStart,
      Metrics::kWiFiLinkQualityTriggerNetworkValidationSuccess,
      Metrics::kWiFiLinkQualityTriggerNetworkValidationFailure,
      Metrics::kWiFiLinkQualityTriggerCQMRSSILow,
      Metrics::kWiFiLinkQualityTriggerCQMRSSIHigh,
      Metrics::kWiFiLinkQualityTriggerCQMBeaconLoss,
      Metrics::kWiFiLinkQualityTriggerCQMPacketLoss,
      Metrics::kWiFiLinkQualityTriggerBackgroundCheck};

  EXPECT_EQ(triggers.size(), expected.size());
  std::vector<Metrics::WiFiLinkQualityTrigger> converted;
  for (auto trigger : triggers) {
    converted.push_back(
        WiFiLinkStatistics::ConvertLinkStatsTriggerEvent(trigger));
  }
  EXPECT_TRUE(std::equal(expected.begin(), expected.end(), converted.begin()));
}

TEST_F(WiFiLinkStatisticsTest, StationInfoReportConvert) {
  // Assign an arbitrary value to the fields that are not yet supported by
  // the conversion method. That will make the test fail when the conversion
  // method starts handling those fields, which will ensure that the test also
  // gets updated to handle them.
  constexpr int64_t kNotHandledYet = 31;

  WiFiLinkStatistics::StationStats stats = {
      .inactive_time = kNotHandledYet,
      .tx_retries = 50,
      .tx_failed = 3,
      .beacon_losses = 12,
      .expected_throughput = 8660,
      .fcs_errors = kNotHandledYet,
      .rx_mpdus = kNotHandledYet,
      .frequency = kNotHandledYet,
      .rx_drop_misc = 5,
      .beacons = 400,
      .signal = kNotHandledYet,
      .noise = kNotHandledYet,
      .signal_avg = kNotHandledYet,
      .beacon_signal_avg = -60,
      .ack_signal_avg = kNotHandledYet,
      .last_ack_signal = kNotHandledYet,
      .center_frequency1 = kNotHandledYet,
      .center_frequency2 = kNotHandledYet,
      .rx =
          {
              .packets = 1500,
              .bytes = 8000,
              .bitrate = 100,
              .mcs = 9,
              .nss = 2,
              .dcm = 0,
          },
      .tx =
          {
              .packets = 1300,
              .bytes = 7000,
              .bitrate = 200,
              .mcs = 7,
              .nss = 2,
              .dcm = 1,
          },
  };

  Metrics::WiFiLinkQualityReport expected = {
      .tx_retries = 50,
      .tx_failures = 3,
      .rx_drops = 5,
      .beacon_signal_avg = -60,
      .beacons_received = 400,
      .beacons_lost = 12,
      .expected_throughput = 8660,
      .rx =
          {
              .packets = 1500,
              .bytes = 8000,
              .bitrate = 100,
              .mcs = 9,
              .nss = 2,
              .dcm = 0,
          },
      .tx =
          {
              .packets = 1300,
              .bytes = 7000,
              .bitrate = 200,
              .mcs = 7,
              .nss = 2,
              .dcm = 1,
          },
  };

  std::vector<WiFiLinkStatistics::ChannelWidth> widths = {
      WiFiLinkStatistics::ChannelWidth::kChannelWidthUnknown,
      WiFiLinkStatistics::ChannelWidth::kChannelWidth20MHz,
      WiFiLinkStatistics::ChannelWidth::kChannelWidth40MHz,
      WiFiLinkStatistics::ChannelWidth::kChannelWidth80MHz,
      WiFiLinkStatistics::ChannelWidth::kChannelWidth80p80MHz,
      WiFiLinkStatistics::ChannelWidth::kChannelWidth160MHz,
      WiFiLinkStatistics::ChannelWidth::kChannelWidth320MHz,
  };
  std::vector<Metrics::WiFiChannelWidth> expected_widths = {
      Metrics::kWiFiChannelWidthUnknown,  Metrics::kWiFiChannelWidth20MHz,
      Metrics::kWiFiChannelWidth40MHz,    Metrics::kWiFiChannelWidth80MHz,
      Metrics::kWiFiChannelWidth80p80MHz, Metrics::kWiFiChannelWidth160MHz,
      Metrics::kWiFiChannelWidth320MHz,
  };
  EXPECT_EQ(widths.size(), expected_widths.size());

  WiFiLinkStatistics::StationStats s = stats;
  Metrics::WiFiLinkQualityReport e = expected;
  for (auto it = widths.begin(); it != widths.end(); ++it) {
    s.width = *it;
    e.width = expected_widths[it - widths.begin()];
    EXPECT_EQ(e, WiFiLinkStatistics::ConvertLinkStatsReport(s));
  }

  std::vector<WiFiLinkStatistics::LinkMode> modes = {
      WiFiLinkStatistics::LinkMode::kLinkModeUnknown,
      WiFiLinkStatistics::LinkMode::kLinkModeLegacy,
      WiFiLinkStatistics::LinkMode::kLinkModeVHT,
      WiFiLinkStatistics::LinkMode::kLinkModeHE,
      WiFiLinkStatistics::LinkMode::kLinkModeEHT,
  };
  std::vector<Metrics::WiFiLinkMode> expected_modes = {
      Metrics::kWiFiLinkModeUnknown, Metrics::kWiFiLinkModeLegacy,
      Metrics::kWiFiLinkModeVHT,     Metrics::kWiFiLinkModeHE,
      Metrics::kWiFiLinkModeEHT,
  };
  EXPECT_EQ(modes.size(), expected_modes.size());

  s = stats;
  e = expected;
  for (auto it = modes.begin(); it != modes.end(); ++it) {
    s.rx.mode = *it;
    e.rx.mode = expected_modes[it - modes.begin()];
    EXPECT_EQ(e, WiFiLinkStatistics::ConvertLinkStatsReport(s));
  }
  s = stats;
  e = expected;
  for (auto it = modes.begin(); it != modes.end(); ++it) {
    s.tx.mode = *it;
    e.tx.mode = expected_modes[it - modes.begin()];
    EXPECT_EQ(e, WiFiLinkStatistics::ConvertLinkStatsReport(s));
  }

  std::vector<WiFiLinkStatistics::GuardInterval> gi = {
      WiFiLinkStatistics::GuardInterval::kLinkStatsGIUnknown,
      WiFiLinkStatistics::GuardInterval::kLinkStatsGI_0_4,
      WiFiLinkStatistics::GuardInterval::kLinkStatsGI_0_8,
      WiFiLinkStatistics::GuardInterval::kLinkStatsGI_1_6,
      WiFiLinkStatistics::GuardInterval::kLinkStatsGI_3_2,
  };
  std::vector<Metrics::WiFiGuardInterval> expected_gi = {
      Metrics::kWiFiGuardIntervalUnknown, Metrics::kWiFiGuardInterval_0_4,
      Metrics::kWiFiGuardInterval_0_8,    Metrics::kWiFiGuardInterval_1_6,
      Metrics::kWiFiGuardInterval_3_2,
  };
  EXPECT_EQ(gi.size(), expected_gi.size());

  s = stats;
  e = expected;
  for (auto it = gi.begin(); it != gi.end(); ++it) {
    s.rx.gi = *it;
    e.rx.gi = expected_gi[it - gi.begin()];
    EXPECT_EQ(e, WiFiLinkStatistics::ConvertLinkStatsReport(s));
  }
  s = stats;
  e = expected;
  for (auto it = gi.begin(); it != gi.end(); ++it) {
    s.tx.gi = *it;
    e.tx.gi = expected_gi[it - gi.begin()];
    EXPECT_EQ(e, WiFiLinkStatistics::ConvertLinkStatsReport(s));
  }
}

TEST_F(WiFiLinkStatisticsTest, StationStatsFromKVHE) {
  KeyValueStore properties;
  properties.Set<int32_t>(WPASupplicant::kSignalChangePropertyRSSI, -70);
  properties.Set<int32_t>(WPASupplicant::kSignalChangePropertyAverageRSSI, -62);
  properties.Set<int32_t>(WPASupplicant::kSignalChangePropertyLastAckRSSI, -90);
  properties.Set<int32_t>(WPASupplicant::kSignalChangePropertyAverageBeaconRSSI,
                          -50);
  properties.Set<int32_t>(WPASupplicant::kSignalChangePropertyAverageAckRSSI,
                          -65);
  properties.Set<int32_t>(WPASupplicant::kSignalChangePropertyNoise, 11);
  properties.Set<int32_t>(WPASupplicant::kSignalChangePropertyCenterFreq1,
                          6200);
  properties.Set<int32_t>(WPASupplicant::kSignalChangePropertyCenterFreq2,
                          6000);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRetries, 400UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRetriesFailed,
                           10UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRxPackets,
                           1000UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyTxPackets,
                           1500UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRxSpeed,
                           86600UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyTxSpeed,
                           50000UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyInactiveTime,
                           150000UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyBeaconLosses,
                           25UL);
  properties.Set<uint32_t>(
      WPASupplicant::kSignalChangePropertyExpectedThroughput, 2400UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyFCSErrors, 2UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRxMPDUS, 15UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyChannelFrequency,
                           65299UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRxHENSS, 8UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyTxHENSS, 6UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRxHEMCS, 15UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyTxHEMCS, 12UL);
  properties.Set<uint64_t>(WPASupplicant::kSignalChangePropertyRxDropMisc,
                           40ULL);
  properties.Set<uint64_t>(WPASupplicant::kSignalChangePropertyRxBytes,
                           8000ULL);
  properties.Set<uint64_t>(WPASupplicant::kSignalChangePropertyTxBytes,
                           10000ULL);
  properties.Set<uint64_t>(WPASupplicant::kSignalChangePropertyBeacons,
                           1000ULL);
  properties.Set<std::string>(WPASupplicant::kSignalChangePropertyChannelWidth,
                              "160 MHz");
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRxDCM, 0);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyTxDCM, 1);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRxGI, 3);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyTxGI, 4);

  WiFiLinkStatistics::StationStats expected = {
      .inactive_time = 150000UL,
      .tx_retries = 400UL,
      .tx_failed = 10UL,
      .beacon_losses = 25UL,
      .expected_throughput = 2400UL,
      .fcs_errors = 2UL,
      .rx_mpdus = 15UL,
      .frequency = 65299UL,
      .rx_drop_misc = 40ULL,
      .beacons = 1000ULL,
      .signal = -70,
      .noise = 11,
      .signal_avg = -62,
      .beacon_signal_avg = -50,
      .ack_signal_avg = -65,
      .last_ack_signal = -90,
      .center_frequency1 = 6200,
      .center_frequency2 = 6000,
      .width = WiFiLinkStatistics::ChannelWidth::kChannelWidth160MHz,
      .rx =
          {
              .packets = 1000UL,
              .bytes = 8000ULL,
              .bitrate = 866UL,
              .mcs = 15,
              .mode = WiFiLinkStatistics::LinkMode::kLinkModeHE,
              .gi = WiFiLinkStatistics::GuardInterval::kLinkStatsGI_1_6,
              .nss = 8,
              .dcm = 0,
          },
      .tx = {
          .packets = 1500UL,
          .bytes = 10000ULL,
          .bitrate = 500UL,
          .mcs = 12,
          .mode = WiFiLinkStatistics::LinkMode::kLinkModeHE,
          .gi = WiFiLinkStatistics::GuardInterval::kLinkStatsGI_3_2,
          .nss = 6,
          .dcm = 1,
      }};

  WiFiLinkStatistics::StationStats stats =
      WiFiLinkStatistics::StationStatsFromSupplicantKV(properties);

  EXPECT_EQ(stats, expected);
}

TEST_F(WiFiLinkStatisticsTest, StationStatsFromKVVHT) {
  KeyValueStore properties;
  properties.Set<int32_t>(WPASupplicant::kSignalChangePropertyRSSI, -70);
  properties.Set<int32_t>(WPASupplicant::kSignalChangePropertyAverageRSSI, -62);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRetries, 400UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRetriesFailed,
                           10UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRxPackets,
                           1000UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyTxPackets,
                           1500UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRxSpeed,
                           86600UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyTxSpeed,
                           50000UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRxVHTNSS, 8UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyTxVHTNSS, 6UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRxVHTMCS, 15UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyTxVHTMCS, 12UL);
  properties.Set<uint64_t>(WPASupplicant::kSignalChangePropertyRxDropMisc,
                           40ULL);
  properties.Set<uint64_t>(WPASupplicant::kSignalChangePropertyRxBytes,
                           8000ULL);
  properties.Set<uint64_t>(WPASupplicant::kSignalChangePropertyTxBytes,
                           10000ULL);
  properties.Set<std::string>(WPASupplicant::kSignalChangePropertyChannelWidth,
                              "80 MHz");
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRxGI, 0);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyTxGI, 1);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyInactiveTime,
                           2000UL);

  WiFiLinkStatistics::StationStats expected = {
      .inactive_time = 2000UL,
      .tx_retries = 400UL,
      .tx_failed = 10UL,
      .rx_drop_misc = 40ULL,
      .signal = -70,
      .signal_avg = -62,
      .width = WiFiLinkStatistics::ChannelWidth::kChannelWidth80MHz,
      .rx =
          {
              .packets = 1000UL,
              .bytes = 8000ULL,
              .bitrate = 866UL,
              .mcs = 15,
              .mode = WiFiLinkStatistics::LinkMode::kLinkModeVHT,
              .gi = WiFiLinkStatistics::GuardInterval::kLinkStatsGIUnknown,
              .nss = 8,
          },
      .tx = {
          .packets = 1500UL,
          .bytes = 10000ULL,
          .bitrate = 500UL,
          .mcs = 12,
          .mode = WiFiLinkStatistics::LinkMode::kLinkModeVHT,
          .gi = WiFiLinkStatistics::GuardInterval::kLinkStatsGI_0_4,
          .nss = 6,
      }};

  WiFiLinkStatistics::StationStats stats =
      WiFiLinkStatistics::StationStatsFromSupplicantKV(properties);

  EXPECT_EQ(stats, expected);
}

TEST_F(WiFiLinkStatisticsTest, StationStatsFromKVLegacy) {
  KeyValueStore properties;
  properties.Set<int32_t>(WPASupplicant::kSignalChangePropertyRSSI, -70);
  properties.Set<int32_t>(WPASupplicant::kSignalChangePropertyAverageRSSI, -62);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRetries, 400UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRetriesFailed,
                           10UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRxPackets,
                           1000UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyTxPackets,
                           1500UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRxSpeed,
                           86600UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyTxSpeed,
                           50000UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRxMCS, 15UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyTxMCS, 12UL);
  properties.Set<uint64_t>(WPASupplicant::kSignalChangePropertyRxDropMisc,
                           40ULL);
  properties.Set<uint64_t>(WPASupplicant::kSignalChangePropertyRxBytes,
                           8000ULL);
  properties.Set<uint64_t>(WPASupplicant::kSignalChangePropertyTxBytes,
                           10000ULL);

  WiFiLinkStatistics::StationStats expected = {
      .tx_retries = 400UL,
      .tx_failed = 10UL,
      .rx_drop_misc = 40ULL,
      .signal = -70,
      .signal_avg = -62,
      .rx =
          {
              .packets = 1000UL,
              .bytes = 8000ULL,
              .bitrate = 866UL,
              .mcs = 15,
              .mode = WiFiLinkStatistics::LinkMode::kLinkModeLegacy,
          },
      .tx = {
          .packets = 1500UL,
          .bytes = 10000ULL,
          .bitrate = 500UL,
          .mcs = 12,
          .mode = WiFiLinkStatistics::LinkMode::kLinkModeLegacy,
      }};

  WiFiLinkStatistics::StationStats stats =
      WiFiLinkStatistics::StationStatsFromSupplicantKV(properties);

  EXPECT_EQ(stats, expected);
}

TEST_F(WiFiLinkStatisticsTest, StationStatsFromKVUnknown) {
  KeyValueStore properties;
  properties.Set<int32_t>(WPASupplicant::kSignalChangePropertyRSSI, -70);
  properties.Set<int32_t>(WPASupplicant::kSignalChangePropertyAverageRSSI, -62);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRetries, 400UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRetriesFailed,
                           10UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRxPackets,
                           1000UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyTxPackets,
                           1500UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyRxSpeed,
                           86600UL);
  properties.Set<uint32_t>(WPASupplicant::kSignalChangePropertyTxSpeed,
                           50000UL);
  properties.Set<uint64_t>(WPASupplicant::kSignalChangePropertyRxDropMisc,
                           40ULL);
  properties.Set<uint64_t>(WPASupplicant::kSignalChangePropertyRxBytes,
                           8000ULL);
  properties.Set<uint64_t>(WPASupplicant::kSignalChangePropertyTxBytes,
                           10000ULL);
  properties.Set<std::string>(WPASupplicant::kSignalChangePropertyChannelWidth,
                              "Invalid Value");

  WiFiLinkStatistics::StationStats expected = {
      .tx_retries = 400UL,
      .tx_failed = 10UL,
      .rx_drop_misc = 40ULL,
      .signal = -70,
      .signal_avg = -62,
      .width = WiFiLinkStatistics::ChannelWidth::kChannelWidthUnknown,
      .rx =
          {
              .packets = 1000UL,
              .bytes = 8000ULL,
              .bitrate = 866UL,
              .mode = WiFiLinkStatistics::LinkMode::kLinkModeUnknown,
          },
      .tx = {
          .packets = 1500UL,
          .bytes = 10000ULL,
          .bitrate = 500UL,
          .mode = WiFiLinkStatistics::LinkMode::kLinkModeUnknown,
      }};

  WiFiLinkStatistics::StationStats stats =
      WiFiLinkStatistics::StationStatsFromSupplicantKV(properties);

  EXPECT_EQ(stats, expected);
}

}  // namespace shill
