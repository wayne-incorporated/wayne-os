// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi_cqm.h"

#include <fcntl.h>
#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>

#include "shill/logging.h"
#include "shill/metrics.h"
#include "shill/net/nl80211_message.h"
#include "shill/scope_logger.h"
#include "shill/wifi/wifi.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kWiFi;
}  // namespace Logging

namespace {
constexpr int16_t kTriggerFwDumpThresholdDbm = -80;
// Have a large enough time interval to rate limit the number of
// triggered FW dumps from shill.
constexpr auto kFwDumpCoolDownPeriod = base::Seconds(360);
constexpr char kFwDumpIntelSysFs[] =
    "/sys/kernel/debug/ieee80211/phy0/iwlwifi/iwlmvm/fw_dbg_collect";

bool WriteToFwDumpSysPath(const base::FilePath& path) {
  base::ScopedFD fd(HANDLE_EINTR(open(path.value().c_str(), O_WRONLY)));
  if (!fd.is_valid()) {
    LOG(ERROR) << "Failed to open sysfs file"
               << ", " << path.value();
    return false;
  }

  if (!base::WriteFileDescriptor(fd.get(), "1")) {
    LOG(ERROR) << "failed to write to sys fs FW dump file";
    return false;
  }

  return true;
}

// Currently it supports Intel and this will support other chipsets once
// they are enabled.
void SetUpFwDumpPath(base::FilePath* path) {
  if (base::PathExists(base::FilePath(kFwDumpIntelSysFs))) {
    *path = base::FilePath(kFwDumpIntelSysFs);
    return;
  }

  // Path existence check for new chipsets goes here.
}

}  // namespace

// CQM thresholds for RSSI notification and Packet loss is configurable
// in kernel; Currently default kernel CQM thresholds are used.
// TODO(b/197597374) : Feature to configure CQM thresholds.
WiFiCQM::WiFiCQM(Metrics* metrics, WiFi* wifi)
    : wifi_(wifi), metrics_(metrics) {
  CHECK(wifi_) << "Passed wifi object was found null.";
  CHECK(metrics_) << "Passed metrics object was found null.";
  SetUpFwDumpPath(&fw_dump_path_);
  if (fw_dump_path_.empty()) {
    SLOG(2) << "Firmware dump not supported.";
  }
}

WiFiCQM::~WiFiCQM() = default;

void WiFiCQM::TriggerFwDump() {
  if (wifi_ &&
      wifi_->GetSignalLevelForActiveService() < kTriggerFwDumpThresholdDbm) {
    SLOG(2) << "CQM notification for signal strength less than "
            << kTriggerFwDumpThresholdDbm << " dBm, Ignore.";
    return;
  }

  if (fw_dump_path_.empty()) {
    SLOG(2) << "FW dump is not supported, cannot trigger FW dump.";
    return;
  }

  auto current = base::Time::NowFromSystemTime();

  if (current < (previous_fw_dump_time_ + kFwDumpCoolDownPeriod) &&
      fw_dump_count_) {
    auto time_left = previous_fw_dump_time_ + kFwDumpCoolDownPeriod - current;
    SLOG(2) << "In FW dump cool down period, no FW dump triggered, "
            << "Time left (in sec): " << time_left.InSecondsF() << " "
            << "Cool down period (in sec): "
            << kFwDumpCoolDownPeriod.InSecondsF();
    return;
  }

  fw_dump_count_++;

  SLOG(2) << "Triggering FW dump.";
  if (WriteToFwDumpSysPath(fw_dump_path_)) {
    SLOG(2) << "FW dump trigger succeeded.";
  }

  previous_fw_dump_time_ = current;
}

void WiFiCQM::OnCQMNotify(const Nl80211Message& nl80211_message) {
  if (nl80211_message.command() != NotifyCqmMessage::kCommand) {
    LOG(ERROR) << __func__
               << ": unexpected command: " << nl80211_message.command_string();
    return;
  }

  AttributeListConstRefPtr cqm_attrs;
  if (!nl80211_message.const_attributes()->ConstGetNestedAttributeList(
          NL80211_ATTR_CQM, &cqm_attrs)) {
    LOG(ERROR) << "Could not find NL80211_ATTR_CQM tag.";
    return;
  }

  // Return after RSSI message is processed. The CQM in kernel is designed to
  // publish one notification type in a given CQM message.
  uint32_t trigger_state;
  if (cqm_attrs->GetU32AttributeValue(NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT,
                                      &trigger_state)) {
    SLOG(2) << "CQM NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT event found.";
    if (trigger_state == NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW) {
      wifi_->EmitStationInfoRequestEvent(
          WiFiLinkStatistics::Trigger::kCQMRSSILow);
    } else {
      wifi_->EmitStationInfoRequestEvent(
          WiFiLinkStatistics::Trigger::kCQMRSSIHigh);
    }
    return;
  }

  uint32_t packet_loss;
  if (cqm_attrs->GetU32AttributeValue(NL80211_ATTR_CQM_PKT_LOSS_EVENT,
                                      &packet_loss)) {
    SLOG(2) << "CQM Packet loss event received, total packet losses: "
            << packet_loss;
    metrics_->SendEnumToUMA(Metrics::kMetricWiFiCQMNotification,
                            Metrics::kWiFiCQMPacketLoss, Metrics::kWiFiCQMMax);
    wifi_->EmitStationInfoRequestEvent(
        WiFiLinkStatistics::Trigger::kCQMPacketLoss);
    // TODO(b/286985004): Uncomment TriggerFWDump() once FW dump in feedback
    // report feature is completed.
    // TriggerFwDump();
    return;
  }

  bool beacon_flag;
  if (cqm_attrs->GetFlagAttributeValue(NL80211_ATTR_CQM_BEACON_LOSS_EVENT,
                                       &beacon_flag)) {
    SLOG(2) << "CQM notification for Beacon loss observed.";
    metrics_->SendEnumToUMA(Metrics::kMetricWiFiCQMNotification,
                            Metrics::kWiFiCQMBeaconLoss, Metrics::kWiFiCQMMax);
    wifi_->EmitStationInfoRequestEvent(
        WiFiLinkStatistics::Trigger::kCQMBeaconLoss);
    // TODO(b/286985004): Enable FW dump trigger once FW dump in feedback
    // report feature is completed.
    // TriggerFwDump();
    return;
  }
}

}  // namespace shill
