// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi_link_statistics.h"

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <base/containers/fixed_flat_map.h>
#include <base/strings/strcat.h>
#include <base/strings/string_piece.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/store/key_value_store.h"
#include "shill/supplicant/wpa_supplicant.h"

namespace shill {
namespace {

constexpr auto kLinkModeTranslationMap =
    base::MakeFixedFlatMap<base::StringPiece, WiFiLinkStatistics::LinkMode>({
        {WPASupplicant::kSignalChangePropertyRxHEMCS,
         WiFiLinkStatistics::LinkMode::kLinkModeHE},
        {WPASupplicant::kSignalChangePropertyRxVHTMCS,
         WiFiLinkStatistics::LinkMode::kLinkModeVHT},
        {WPASupplicant::kSignalChangePropertyRxMCS,
         WiFiLinkStatistics::LinkMode::kLinkModeLegacy},
        {WPASupplicant::kSignalChangePropertyTxHEMCS,
         WiFiLinkStatistics::LinkMode::kLinkModeHE},
        {WPASupplicant::kSignalChangePropertyTxVHTMCS,
         WiFiLinkStatistics::LinkMode::kLinkModeVHT},
        {WPASupplicant::kSignalChangePropertyTxMCS,
         WiFiLinkStatistics::LinkMode::kLinkModeLegacy},
    });

// Undo the work of channel_width_to_string at:
// https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/third_party/wpa_supplicant-cros/next/src/drivers/driver_common.c;l=100
constexpr auto kChannelWidthTranslationMap =
    base::MakeFixedFlatMap<base::StringPiece, WiFiLinkStatistics::ChannelWidth>(
        {
            {WPASupplicant::kChannelWidth20MHznoHT,
             WiFiLinkStatistics::ChannelWidth::kChannelWidth20MHz},
            {WPASupplicant::kChannelWidth20MHz,
             WiFiLinkStatistics::ChannelWidth::kChannelWidth20MHz},
            {WPASupplicant::kChannelWidth40MHz,
             WiFiLinkStatistics::ChannelWidth::kChannelWidth40MHz},
            {WPASupplicant::kChannelWidth80MHz,
             WiFiLinkStatistics::ChannelWidth::kChannelWidth80MHz},
            {WPASupplicant::kChannelWidth80p80MHz,
             WiFiLinkStatistics::ChannelWidth::kChannelWidth80p80MHz},
            {WPASupplicant::kChannelWidth160MHz,
             WiFiLinkStatistics::ChannelWidth::kChannelWidth160MHz},
        });

// See guard_interval at:
// https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/third_party/wpa_supplicant-cros/next/src/drivers/driver.h
constexpr auto kGuardIntervalTranslationMap =
    base::MakeFixedFlatMap<uint32_t, WiFiLinkStatistics::GuardInterval>({
        {WPASupplicant::kGuardInterval_0_4,
         WiFiLinkStatistics::GuardInterval::kLinkStatsGI_0_4},
        {WPASupplicant::kGuardInterval_0_8,
         WiFiLinkStatistics::GuardInterval::kLinkStatsGI_0_8},
        {WPASupplicant::kGuardInterval_1_6,
         WiFiLinkStatistics::GuardInterval::kLinkStatsGI_1_6},
        {WPASupplicant::kGuardInterval_3_2,
         WiFiLinkStatistics::GuardInterval::kLinkStatsGI_3_2},
    });

bool IsNetworkEvent(WiFiLinkStatistics::Trigger trigger) {
  // Only update the state if the link statistics request was triggered by an
  // IP-level event, not lower level events like periodic checks or CQM.
  return trigger == WiFiLinkStatistics::Trigger::kIPConfigurationStart ||
         trigger == WiFiLinkStatistics::Trigger::kConnected ||
         trigger == WiFiLinkStatistics::Trigger::kDHCPRenewOnRoam ||
         trigger == WiFiLinkStatistics::Trigger::kDHCPSuccess ||
         trigger == WiFiLinkStatistics::Trigger::kDHCPFailure ||
         trigger == WiFiLinkStatistics::Trigger::kSlaacFinished ||
         trigger == WiFiLinkStatistics::Trigger::kNetworkValidationStart ||
         trigger == WiFiLinkStatistics::Trigger::kNetworkValidationSuccess ||
         trigger == WiFiLinkStatistics::Trigger::kNetworkValidationFailure;
}

// Determine if the WiFi link statistics should be print to log.
bool ShouldPrintWiFiLinkStatistics(WiFiLinkStatistics::Trigger trigger) {
  // It doesn't consider if the service is connected (Service::IsConnected() ==
  // true) when determining if the WiFi link statistics should be printed.
  // There are two examples where the service is connected, but the necessity of
  // WiFi link statistics differs.

  // 1. For IPv6-only networks, the network event transition may be
  // kIPConfigurationStart -> kSlaacFinished -> kConnected -> kDHCPFailure, the
  // WiFi link statistics should not be printed.
  // 2. Suppose a device has a static IPv4 configuration but it still needs DHCP
  // to succeed (to obtain vendor options, like proxy settings) and DHCP fails
  // due to poor link connection, the WiFi link statistics should be printed.

  // It may print unnecessary WiFi link statistics if the state of the service
  // is not considered. It is acceptable because the size of the WiFi link
  // statistics in netlog is small.
  return trigger == WiFiLinkStatistics::Trigger::kDHCPFailure ||
         trigger == WiFiLinkStatistics::Trigger::kNetworkValidationFailure;
}

bool IsEndNetworkEvent(WiFiLinkStatistics::Trigger trigger) {
  return trigger == WiFiLinkStatistics::Trigger::kConnected ||
         trigger == WiFiLinkStatistics::Trigger::kDHCPSuccess ||
         trigger == WiFiLinkStatistics::Trigger::kDHCPFailure ||
         trigger == WiFiLinkStatistics::Trigger::kSlaacFinished ||
         trigger == WiFiLinkStatistics::Trigger::kNetworkValidationSuccess ||
         trigger == WiFiLinkStatistics::Trigger::kNetworkValidationFailure;
}

bool DoesEndMatchStartEvent(WiFiLinkStatistics::Trigger start_event,
                            WiFiLinkStatistics::Trigger end_event) {
  // kIPConfigurationStart is used to represent IPv4 and IPv6 configuration
  // start, so kConnected doesn't actually have a corresponding start event.
  switch (end_event) {
    case WiFiLinkStatistics::Trigger::kDHCPSuccess:
    case WiFiLinkStatistics::Trigger::kDHCPFailure:
      return start_event ==
                 WiFiLinkStatistics::Trigger::kIPConfigurationStart ||
             start_event == WiFiLinkStatistics::Trigger::kDHCPRenewOnRoam;
    case WiFiLinkStatistics::Trigger::kSlaacFinished:
      return start_event == WiFiLinkStatistics::Trigger::kIPConfigurationStart;
    case WiFiLinkStatistics::Trigger::kNetworkValidationSuccess:
    case WiFiLinkStatistics::Trigger::kNetworkValidationFailure:
      return start_event ==
             WiFiLinkStatistics::Trigger::kNetworkValidationStart;
    default:
      return false;
  }
}

// Calculate the difference between NL80211 link statistics old_stats and
// new_stats
WiFiLinkStatistics::StationStats Nl80211LinkStatisticsDiff(
    const WiFiLinkStatistics::StationStats& old_stats,
    const WiFiLinkStatistics::StationStats& new_stats) {
  WiFiLinkStatistics::StationStats diff_stats;
  diff_stats.rx.packets = new_stats.rx.packets - old_stats.rx.packets;
  diff_stats.tx.packets = new_stats.tx.packets - old_stats.tx.packets;
  diff_stats.rx.bytes = new_stats.rx.bytes - old_stats.rx.bytes;
  diff_stats.tx.bytes = new_stats.tx.bytes - old_stats.tx.bytes;
  diff_stats.tx_failed = new_stats.tx_failed - old_stats.tx_failed;
  diff_stats.tx_retries = new_stats.tx_retries - old_stats.tx_retries;
  diff_stats.rx_drop_misc = new_stats.rx_drop_misc - old_stats.rx_drop_misc;
  diff_stats.signal = new_stats.signal;
  diff_stats.signal_avg = new_stats.signal_avg;
  return diff_stats;
}

// Calculate the difference between RTNL link statistics old_stats and
// new_stats
old_rtnl_link_stats64 RtnlLinkStatisticsDiff(
    const old_rtnl_link_stats64& old_stats,
    const old_rtnl_link_stats64& new_stats) {
  old_rtnl_link_stats64 diff_stats;
  diff_stats.rx_packets = new_stats.rx_packets - old_stats.rx_packets;
  diff_stats.tx_packets = new_stats.tx_packets - old_stats.tx_packets;
  diff_stats.rx_bytes = new_stats.rx_bytes - old_stats.rx_bytes;
  diff_stats.tx_bytes = new_stats.tx_bytes - old_stats.tx_bytes;
  diff_stats.rx_errors = new_stats.rx_errors - old_stats.rx_errors;
  diff_stats.tx_errors = new_stats.tx_errors - old_stats.tx_errors;
  diff_stats.rx_dropped = new_stats.rx_dropped - old_stats.rx_dropped;
  diff_stats.tx_dropped = new_stats.tx_dropped - old_stats.tx_dropped;
  return diff_stats;
}

// Convert RTNL link statistics to string
std::string RtnlLinkStatisticsToString(
    const old_rtnl_link_stats64& diff_stats) {
  return base::StrCat({"rx_packets ", std::to_string(diff_stats.rx_packets),
                       " tx_packets ", std::to_string(diff_stats.tx_packets),
                       " rx_bytes ", std::to_string(diff_stats.rx_bytes),
                       " tx_bytes ", std::to_string(diff_stats.tx_bytes),
                       " rx_errors ", std::to_string(diff_stats.rx_errors),
                       " tx_errors ", std::to_string(diff_stats.tx_errors),
                       " rx_dropped ", std::to_string(diff_stats.rx_dropped),
                       " tx_dropped ", std::to_string(diff_stats.tx_dropped)});
}

// Convert NL80211 link statistics to string
std::string Nl80211LinkStatisticsToString(
    const WiFiLinkStatistics::StationStats& diff_stats) {
  return base::StrCat({kPacketReceiveSuccessesProperty,
                       " ",
                       std::to_string(diff_stats.rx.packets),
                       " ",
                       kPacketTransmitSuccessesProperty,
                       " ",
                       std::to_string(diff_stats.tx.packets),
                       " ",
                       kByteReceiveSuccessesProperty,
                       " ",
                       std::to_string(diff_stats.rx.bytes),
                       " ",
                       kByteTransmitSuccessesProperty,
                       " ",
                       std::to_string(diff_stats.tx.bytes),
                       " ",
                       kPacketTransmitFailuresProperty,
                       " ",
                       std::to_string(diff_stats.tx_failed),
                       " ",
                       kTransmitRetriesProperty,
                       " ",
                       std::to_string(diff_stats.tx_retries),
                       " ",
                       kPacketReceiveDropProperty,
                       " ",
                       std::to_string(diff_stats.rx_drop_misc),
                       "; the current signal information: ",
                       kLastReceiveSignalDbmProperty,
                       " ",
                       std::to_string(diff_stats.signal),
                       " ",
                       kAverageReceiveSignalDbmProperty,
                       " ",
                       std::to_string(diff_stats.signal_avg)});
}

std::string ConvertToBitrateString(WiFiLinkStatistics::ChannelWidth width,
                                   WiFiLinkStatistics::RxTxStats link_stats) {
  std::string mcs_str;
  switch (link_stats.mode) {
    case WiFiLinkStatistics::LinkMode::kLinkModeLegacy:
      mcs_str = base::StringPrintf(" MCS %d", link_stats.mcs);
      break;
    case WiFiLinkStatistics::LinkMode::kLinkModeVHT:
      mcs_str = base::StringPrintf(" VHT-MCS %d", link_stats.mcs);
      break;
    default:
      break;
  }

  std::string nss_str;
  WiFiLinkStatistics::RxTxStats defaults;
  if (link_stats.nss != defaults.nss) {
    nss_str = base::StringPrintf(" VHT-NSS %d", link_stats.nss);
  }

  std::string width_str;
  switch (width) {
    case WiFiLinkStatistics::ChannelWidth::kChannelWidth40MHz:
      width_str = base::StringPrintf(" 40MHz");
      break;
    case WiFiLinkStatistics::ChannelWidth::kChannelWidth80MHz:
      width_str = base::StringPrintf(" 80MHz");
      break;
    case WiFiLinkStatistics::ChannelWidth::kChannelWidth80p80MHz:
      width_str = base::StringPrintf(" 80+80MHz");
      break;
    case WiFiLinkStatistics::ChannelWidth::kChannelWidth160MHz:
      width_str = base::StringPrintf(" 160MHz");
      break;
    default:
      break;
  }

  std::string out = base::StringPrintf(
      "%d.%d MBit/s%s%s%s%s", link_stats.bitrate / 10, link_stats.bitrate % 10,
      mcs_str.c_str(), width_str.c_str(),
      link_stats.gi == WiFiLinkStatistics::GuardInterval::kLinkStatsGI_0_4
          ? " short GI"
          : "",
      nss_str.c_str());
  return out;
}

Metrics::WiFiChannelWidth ConvertChannelWidth(
    WiFiLinkStatistics::ChannelWidth w) {
  Metrics::WiFiChannelWidth width = Metrics::kWiFiChannelWidthUnknown;
  switch (w) {
    case WiFiLinkStatistics::ChannelWidth::kChannelWidth20MHz:
      width = Metrics::kWiFiChannelWidth20MHz;
      break;
    case WiFiLinkStatistics::ChannelWidth::kChannelWidth40MHz:
      width = Metrics::kWiFiChannelWidth40MHz;
      break;
    case WiFiLinkStatistics::ChannelWidth::kChannelWidth80MHz:
      width = Metrics::kWiFiChannelWidth80MHz;
      break;
    case WiFiLinkStatistics::ChannelWidth::kChannelWidth80p80MHz:
      width = Metrics::kWiFiChannelWidth80p80MHz;
      break;
    case WiFiLinkStatistics::ChannelWidth::kChannelWidth160MHz:
      width = Metrics::kWiFiChannelWidth160MHz;
      break;
    case WiFiLinkStatistics::ChannelWidth::kChannelWidth320MHz:
      width = Metrics::kWiFiChannelWidth320MHz;
      break;
    default:
      width = Metrics::kWiFiChannelWidthUnknown;
      break;
  }
  return width;
}

Metrics::WiFiRxTxStats ConvertRxTxStats(
    const WiFiLinkStatistics::RxTxStats& stats) {
  Metrics::WiFiRxTxStats link_stats;
  link_stats.packets = stats.packets;
  link_stats.bytes = stats.bytes;
  link_stats.bitrate = stats.bitrate;
  link_stats.mcs = stats.mcs;

  switch (stats.mode) {
    case WiFiLinkStatistics::LinkMode::kLinkModeLegacy:
      link_stats.mode = Metrics::kWiFiLinkModeLegacy;
      break;
    case WiFiLinkStatistics::LinkMode::kLinkModeVHT:
      link_stats.mode = Metrics::kWiFiLinkModeVHT;
      break;
    case WiFiLinkStatistics::LinkMode::kLinkModeHE:
      link_stats.mode = Metrics::kWiFiLinkModeHE;
      break;
    case WiFiLinkStatistics::LinkMode::kLinkModeEHT:
      link_stats.mode = Metrics::kWiFiLinkModeEHT;
      break;
    default:
      link_stats.mode = Metrics::kWiFiLinkModeUnknown;
      break;
  }
  switch (stats.gi) {
    case WiFiLinkStatistics::GuardInterval::kLinkStatsGI_0_4:
      link_stats.gi = Metrics::kWiFiGuardInterval_0_4;
      break;
    case WiFiLinkStatistics::GuardInterval::kLinkStatsGI_0_8:
      link_stats.gi = Metrics::kWiFiGuardInterval_0_8;
      break;
    case WiFiLinkStatistics::GuardInterval::kLinkStatsGI_1_6:
      link_stats.gi = Metrics::kWiFiGuardInterval_1_6;
      break;
    case WiFiLinkStatistics::GuardInterval::kLinkStatsGI_3_2:
      link_stats.gi = Metrics::kWiFiGuardInterval_3_2;
      break;
    default:
      link_stats.gi = Metrics::kWiFiGuardIntervalUnknown;
      break;
  }
  link_stats.nss = stats.nss;
  link_stats.dcm = stats.dcm;
  return link_stats;
}

}  // namespace

// static
std::string WiFiLinkStatistics::LinkStatisticsTriggerToString(Trigger trigger) {
  switch (trigger) {
    case Trigger::kUnknown:
      return "kUnknown";
    case Trigger::kIPConfigurationStart:
      return "kIPConfigurationStart";
    case Trigger::kConnected:
      return "kConnected";
    case Trigger::kDHCPRenewOnRoam:
      return "kDHCPRenewOnRoam";
    case Trigger::kDHCPSuccess:
      return "kDHCPSuccess";
    case Trigger::kDHCPFailure:
      return "kDHCPFailure";
    case Trigger::kSlaacFinished:
      return "kSlaacFinished";
    case Trigger::kNetworkValidationStart:
      return "kNetworkValidationStart";
    case Trigger::kNetworkValidationSuccess:
      return "kNetworkValidationSuccess";
    case Trigger::kNetworkValidationFailure:
      return "kNetworkValidationFailure";
    default:
      LOG(ERROR) << "Invalid LinkStatisticsTrigger: "
                 << static_cast<unsigned int>(trigger);
      return "Invalid";
  }
}

// static
KeyValueStore WiFiLinkStatistics::StationStatsToWiFiDeviceKV(
    const StationStats& stats) {
  KeyValueStore kv;
  StationStats defaults;
  if (stats.inactive_time != defaults.inactive_time) {
    kv.Set<uint32_t>(kInactiveTimeMillisecondsProperty, stats.inactive_time);
  }
  if (stats.rx.packets != defaults.rx.packets) {
    kv.Set<uint32_t>(kPacketReceiveSuccessesProperty, stats.rx.packets);
  }
  if (stats.tx.packets != defaults.tx.packets) {
    kv.Set<uint32_t>(kPacketTransmitSuccessesProperty, stats.tx.packets);
  }
  if (stats.rx.bytes != defaults.rx.bytes) {
    kv.Set<uint32_t>(kByteReceiveSuccessesProperty, stats.rx.bytes);
  }
  if (stats.tx.bytes != defaults.tx.bytes) {
    kv.Set<uint32_t>(kByteTransmitSuccessesProperty, stats.tx.bytes);
  }
  if (stats.tx_failed != defaults.tx_failed) {
    kv.Set<uint32_t>(kPacketTransmitFailuresProperty, stats.tx_failed);
  }
  if (stats.tx_retries != defaults.tx_retries) {
    kv.Set<uint32_t>(kTransmitRetriesProperty, stats.tx_retries);
  }
  if (stats.rx_drop_misc != defaults.rx_drop_misc) {
    kv.Set<uint64_t>(kPacketReceiveDropProperty, stats.rx_drop_misc);
  }

  if (stats.signal != defaults.signal) {
    kv.Set<int32_t>(kLastReceiveSignalDbmProperty, stats.signal);
  }
  if (stats.signal_avg != defaults.signal_avg) {
    kv.Set<int32_t>(kAverageReceiveSignalDbmProperty, stats.signal_avg);
  }

  if (stats.tx.bitrate != defaults.tx.bitrate) {
    kv.Set<std::string>(kTransmitBitrateProperty,
                        ConvertToBitrateString(stats.width, stats.tx));
  }
  if (stats.rx.bitrate != defaults.rx.bitrate) {
    kv.Set<std::string>(kReceiveBitrateProperty,
                        ConvertToBitrateString(stats.width, stats.rx));
  }
  return kv;
}

// static
WiFiLinkStatistics::StationStats
WiFiLinkStatistics::StationStatsFromSupplicantKV(
    const KeyValueStore& properties) {
  StationStats stats;
  stats.signal =
      properties.Get<int32_t>(WPASupplicant::kSignalChangePropertyRSSI);

  const std::initializer_list<std::pair<base::StringPiece, int32_t*>>
      signal_properties_s32 = {
          {WPASupplicant::kSignalChangePropertyAverageRSSI, &stats.signal_avg},
          {WPASupplicant::kSignalChangePropertyLastAckRSSI,
           &stats.last_ack_signal},
          {WPASupplicant::kSignalChangePropertyAverageBeaconRSSI,
           &stats.beacon_signal_avg},
          {WPASupplicant::kSignalChangePropertyAverageAckRSSI,
           &stats.ack_signal_avg},
          {WPASupplicant::kSignalChangePropertyNoise, &stats.noise},
          {WPASupplicant::kSignalChangePropertyCenterFreq1,
           &stats.center_frequency1},
          {WPASupplicant::kSignalChangePropertyCenterFreq2,
           &stats.center_frequency2},
      };

  for (const auto& kv : signal_properties_s32) {
    if (properties.Contains<int32_t>(kv.first)) {
      *kv.second = properties.Get<int32_t>(kv.first);
    }
  }

  const std::initializer_list<std::pair<base::StringPiece, uint32_t*>>
      signal_properties_u32 = {
          {WPASupplicant::kSignalChangePropertyRetries, &stats.tx_retries},
          {WPASupplicant::kSignalChangePropertyRetriesFailed, &stats.tx_failed},
          {WPASupplicant::kSignalChangePropertyRxPackets, &stats.rx.packets},
          {WPASupplicant::kSignalChangePropertyTxPackets, &stats.tx.packets},
          {WPASupplicant::kSignalChangePropertyRxSpeed, &stats.rx.bitrate},
          {WPASupplicant::kSignalChangePropertyTxSpeed, &stats.tx.bitrate},
          {WPASupplicant::kSignalChangePropertyInactiveTime,
           &stats.inactive_time},
          {WPASupplicant::kSignalChangePropertyBeaconLosses,
           &stats.beacon_losses},
          {WPASupplicant::kSignalChangePropertyExpectedThroughput,
           &stats.expected_throughput},
          {WPASupplicant::kSignalChangePropertyFCSErrors, &stats.fcs_errors},
          {WPASupplicant::kSignalChangePropertyRxMPDUS, &stats.rx_mpdus},
          {WPASupplicant::kSignalChangePropertyChannelFrequency,
           &stats.frequency},
      };

  for (const auto& kv : signal_properties_u32) {
    if (properties.Contains<uint32_t>(kv.first)) {
      *kv.second = properties.Get<uint32_t>(kv.first);
    }
  }

  if (stats.tx.bitrate != UINT_MAX) {
    stats.tx.bitrate = stats.tx.bitrate / 100;
  }
  if (stats.rx.bitrate != UINT_MAX) {
    stats.rx.bitrate = stats.rx.bitrate / 100;
  }

  const std::initializer_list<std::pair<base::StringPiece, uint8_t*>>
      signal_properties_u8 = {
          {WPASupplicant::kSignalChangePropertyRxHENSS, &stats.rx.nss},
          {WPASupplicant::kSignalChangePropertyTxHENSS, &stats.tx.nss},
          {WPASupplicant::kSignalChangePropertyRxVHTNSS, &stats.rx.nss},
          {WPASupplicant::kSignalChangePropertyTxVHTNSS, &stats.tx.nss},
          {WPASupplicant::kSignalChangePropertyRxDCM, &stats.rx.dcm},
          {WPASupplicant::kSignalChangePropertyTxDCM, &stats.tx.dcm},
      };

  for (const auto& kv : signal_properties_u8) {
    if (properties.Contains<uint32_t>(kv.first)) {
      *kv.second = static_cast<uint8_t>(properties.Get<uint32_t>(kv.first));
    }
  }

  const std::initializer_list<
      std::pair<base::StringPiece, WiFiLinkStatistics::RxTxStats*>>
      signal_properties_mcs = {
          {WPASupplicant::kSignalChangePropertyRxHEMCS, &stats.rx},
          {WPASupplicant::kSignalChangePropertyTxHEMCS, &stats.tx},
          {WPASupplicant::kSignalChangePropertyRxVHTMCS, &stats.rx},
          {WPASupplicant::kSignalChangePropertyTxVHTMCS, &stats.tx},
          {WPASupplicant::kSignalChangePropertyRxMCS, &stats.rx},
          {WPASupplicant::kSignalChangePropertyTxMCS, &stats.tx},
      };

  for (const auto& kv : signal_properties_mcs) {
    if (properties.Contains<uint32_t>(kv.first)) {
      kv.second->mcs = static_cast<uint8_t>(properties.Get<uint32_t>(kv.first));
      const auto it = kLinkModeTranslationMap.find(kv.first);
      if (it != kLinkModeTranslationMap.end()) {
        kv.second->mode = it->second;
      }
    }
  }

  const std::initializer_list<std::pair<base::StringPiece, uint64_t*>>
      signal_properties_u64 = {
          {WPASupplicant::kSignalChangePropertyRxDropMisc, &stats.rx_drop_misc},
          {WPASupplicant::kSignalChangePropertyRxBytes, &stats.rx.bytes},
          {WPASupplicant::kSignalChangePropertyTxBytes, &stats.tx.bytes},
          {WPASupplicant::kSignalChangePropertyBeacons, &stats.beacons},
      };

  for (const auto& kv : signal_properties_u64) {
    if (properties.Contains<uint64_t>(kv.first)) {
      *kv.second = properties.Get<uint64_t>(kv.first);
    }
  }

  if (properties.Contains<std::string>(
          WPASupplicant::kSignalChangePropertyChannelWidth)) {
    std::string width = properties.Get<std::string>(
        WPASupplicant::kSignalChangePropertyChannelWidth);

    const auto it = kChannelWidthTranslationMap.find(width);
    if (it == kChannelWidthTranslationMap.end()) {
      stats.width = ChannelWidth::kChannelWidthUnknown;
    } else {
      stats.width = it->second;
    }
  }

  if (properties.Contains<uint32_t>(WPASupplicant::kSignalChangePropertyRxGI)) {
    uint32_t gi =
        properties.Get<uint32_t>(WPASupplicant::kSignalChangePropertyRxGI);
    const auto it = kGuardIntervalTranslationMap.find(gi);
    if (it == kGuardIntervalTranslationMap.end()) {
      stats.rx.gi = GuardInterval::kLinkStatsGIUnknown;
    } else {
      stats.rx.gi = it->second;
    }
  }

  if (properties.Contains<uint32_t>(WPASupplicant::kSignalChangePropertyTxGI)) {
    uint32_t gi =
        properties.Get<uint32_t>(WPASupplicant::kSignalChangePropertyTxGI);
    const auto it = kGuardIntervalTranslationMap.find(gi);
    if (it == kGuardIntervalTranslationMap.end()) {
      stats.tx.gi = GuardInterval::kLinkStatsGIUnknown;
    } else {
      stats.tx.gi = it->second;
    }
  }
  return stats;
}

void WiFiLinkStatistics::Reset() {
  nl80211_link_statistics_.clear();
  rtnl_link_statistics_.clear();
}

void WiFiLinkStatistics::UpdateNl80211LinkStatistics(
    Trigger trigger, const StationStats& stats) {
  if (!IsNetworkEvent(trigger)) {
    return;
  }

  // If the trigger is an end network event, erase the link statistics of its
  // start network event and print the difference to the log if necessary.
  if (IsEndNetworkEvent(trigger)) {
    for (auto it = nl80211_link_statistics_.begin();
         it != nl80211_link_statistics_.end(); it++) {
      if (!DoesEndMatchStartEvent(it->trigger, trigger)) {
        continue;
      }
      if (ShouldPrintWiFiLinkStatistics(trigger)) {
        auto diff_stats =
            Nl80211LinkStatisticsDiff(it->nl80211_link_stats, stats);
        LOG(INFO) << "Network event related to NL80211 link statistics: "
                  << LinkStatisticsTriggerToString(it->trigger) << " -> "
                  << LinkStatisticsTriggerToString(trigger)
                  << "; the NL80211 link statistics delta for the last "
                  << (base::Time::Now() - it->timestamp).InSeconds()
                  << " seconds is "
                  << Nl80211LinkStatisticsToString(diff_stats);
      }
      nl80211_link_statistics_.erase(it);
      break;
    }
  } else {
    // The trigger is a start network event, append this snapshot of link
    // statistics.
    nl80211_link_statistics_.emplace_back(trigger, stats);
    // Add an extra nl80211 link statistics because kIPConfigurationStart
    // corresponds to the start of the initial DHCP lease acquisition by dhcpcd
    // and to the start of IPv6 SLAAC in the kernel.
    if (trigger == Trigger::kIPConfigurationStart) {
      nl80211_link_statistics_.emplace_back(trigger, stats);
    }
  }
}

void WiFiLinkStatistics::UpdateRtnlLinkStatistics(
    Trigger trigger, const old_rtnl_link_stats64& stats) {
  if (trigger == Trigger::kUnknown) {
    return;
  }
  // If the trigger is an end network event, erase the link statistics of its
  // start network event and print the difference to the log if necessary.
  if (IsEndNetworkEvent(trigger)) {
    for (auto it = rtnl_link_statistics_.begin();
         it != rtnl_link_statistics_.end(); it++) {
      if (!DoesEndMatchStartEvent(it->trigger, trigger)) {
        continue;
      }
      if (ShouldPrintWiFiLinkStatistics(trigger)) {
        auto diff_stats = RtnlLinkStatisticsDiff(it->rtnl_link_stats, stats);
        LOG(INFO) << "Network event related to RTNL link statistics: "
                  << LinkStatisticsTriggerToString(it->trigger) << " -> "
                  << LinkStatisticsTriggerToString(trigger)
                  << "; the RTNL link statistics delta for the last "
                  << (base::Time::Now() - it->timestamp).InSeconds()
                  << " seconds is " << RtnlLinkStatisticsToString(diff_stats);
      }
      rtnl_link_statistics_.erase(it);
      break;
    }
  } else {
    // The trigger is a start network event, append this snapshot of link
    // statistics.
    rtnl_link_statistics_.emplace_back(trigger, stats);
    // Add an extra RTNL link statistics because kIPConfigurationStart
    // corresponds to the start of the initial DHCP lease acquisition by dhcpcd
    // and to the start of IPv6 SLAAC in the kernel.
    if (trigger == Trigger::kIPConfigurationStart) {
      rtnl_link_statistics_.emplace_back(trigger, stats);
    }
  }
}

// static
Metrics::WiFiLinkQualityTrigger
WiFiLinkStatistics::ConvertLinkStatsTriggerEvent(Trigger trigger) {
  switch (trigger) {
    case Trigger::kIPConfigurationStart:
      return Metrics::kWiFiLinkQualityTriggerIPConfigurationStart;
    case Trigger::kConnected:
      return Metrics::kWiFiLinkQualityTriggerConnected;
    case Trigger::kDHCPRenewOnRoam:
      return Metrics::kWiFiLinkQualityTriggerDHCPRenewOnRoam;
    case Trigger::kDHCPSuccess:
      return Metrics::kWiFiLinkQualityTriggerDHCPSuccess;
    case Trigger::kDHCPFailure:
      return Metrics::kWiFiLinkQualityTriggerDHCPFailure;
    case Trigger::kSlaacFinished:
      return Metrics::kWiFiLinkQualityTriggerSlaacFinished;
    case Trigger::kNetworkValidationStart:
      return Metrics::kWiFiLinkQualityTriggerNetworkValidationStart;
    case Trigger::kNetworkValidationSuccess:
      return Metrics::kWiFiLinkQualityTriggerNetworkValidationSuccess;
    case Trigger::kNetworkValidationFailure:
      return Metrics::kWiFiLinkQualityTriggerNetworkValidationFailure;
    case Trigger::kCQMRSSILow:
      return Metrics::kWiFiLinkQualityTriggerCQMRSSILow;
    case Trigger::kCQMRSSIHigh:
      return Metrics::kWiFiLinkQualityTriggerCQMRSSIHigh;
    case Trigger::kCQMBeaconLoss:
      return Metrics::kWiFiLinkQualityTriggerCQMBeaconLoss;
    case Trigger::kCQMPacketLoss:
      return Metrics::kWiFiLinkQualityTriggerCQMPacketLoss;
    case Trigger::kBackground:
      return Metrics::kWiFiLinkQualityTriggerBackgroundCheck;
    default:
      return Metrics::kWiFiLinkQualityTriggerUnknown;
  }
}

// static
Metrics::WiFiLinkQualityReport WiFiLinkStatistics::ConvertLinkStatsReport(
    const StationStats& stats) {
  Metrics::WiFiLinkQualityReport report;

  report.tx_retries = stats.tx_retries;
  report.tx_failures = stats.tx_failed;
  report.rx_drops = stats.rx_drop_misc;
  report.beacons_received = stats.beacons;
  report.beacons_lost = stats.beacon_losses;
  report.expected_throughput = stats.expected_throughput;
  report.beacon_signal_avg = stats.beacon_signal_avg;
  report.width = ConvertChannelWidth(stats.width);
  report.rx = ConvertRxTxStats(stats.rx);
  report.tx = ConvertRxTxStats(stats.tx);
  return report;
}

}  // namespace shill
