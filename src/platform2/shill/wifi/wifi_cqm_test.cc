// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi_cqm.h"

#include <memory>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/metrics.h"
#include "shill/mock_control.h"
#include "shill/mock_log.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/net/netlink_packet.h"
#include "shill/net/nl80211_attribute.h"
#include "shill/net/nl80211_message.h"
#include "shill/refptr_types.h"
#include "shill/test_event_dispatcher.h"
#include "shill/wifi/mock_wake_on_wifi.h"
#include "shill/wifi/mock_wifi.h"
#include "shill/wifi/wifi.h"

using ::testing::_;
using ::testing::HasSubstr;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;

namespace shill {

namespace {

// Fake MAC address.
constexpr char kDeviceAddress[] = "aabbccddeeff";
const uint16_t kNl80211FamilyId = 0x13;

// Bytes representing NL80211 CQM message to pass to unit tests.
const uint8_t kCQMBeaconLossNLMsg[] = {
    0x2c, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x08, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x08, 0x00, 0x5e, 0x00, 0x04, 0x00, 0x08, 0x00};

const uint8_t kCQMRssiLowNLMsg[] = {
    0x38, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x14, 0x00, 0x5e, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x09, 0x00, 0xba, 0xff, 0xff, 0xff};

const uint8_t kCQMRssiHighNLMsg[] = {
    0x38, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x14, 0x00, 0x5e, 0x00, 0x08, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x09, 0x00, 0xd8, 0xff, 0xff, 0xff};

const uint8_t kCQMPacketLossNLMsg[] = {
    0x30, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x5e, 0x00, 0x08, 0x00, 0x04, 0x00, 0x32, 0x00, 0x00, 0x00};

}  // namespace

class WiFiCQMTest : public ::testing::Test {
 public:
  WiFiCQMTest()
      : manager_(&control_interface_, &dispatcher_, &metrics_),
        wifi_(new MockWiFi(
            &manager_, "wifi", kDeviceAddress, 0, 0, new MockWakeOnWiFi())),
        wifi_cqm_(new WiFiCQM(&metrics_, wifi().get())) {
    Nl80211Message::SetMessageType(kNl80211FamilyId);
  }

  void SetUp() override {
    CHECK(temp_dir_.CreateUniqueTempDir());
    base::FilePath fw_dump_path =
        temp_dir_.GetPath()
            .Append("sys/kernel/debug/ieee80211/phy0/iwlwifi/iwlmvm")
            .Append("fw_dbg_collect");
    EXPECT_TRUE(base::CreateDirectory(fw_dump_path.DirName()));
    EXPECT_TRUE(base::WriteFile(fw_dump_path, "1", 1));
    EXPECT_TRUE(base::PathExists(fw_dump_path));
    wifi_cqm_->fw_dump_path_ = fw_dump_path;
  }

  void TearDown() override { EXPECT_TRUE(temp_dir_.Delete()); }

  ~WiFiCQMTest() override = default;

 protected:
  // Used to create a virtual sysfs path.
  base::ScopedTempDir temp_dir_;

  MockMetrics* metrics() { return &metrics_; }

  void OnCQMNotify(const Nl80211Message& nl80211_message) {
    wifi_cqm_->OnCQMNotify(nl80211_message);
  }

  void TriggerFwDump() { return wifi_cqm_->TriggerFwDump(); }

  int FwDumpCount() { return wifi_cqm_->fw_dump_count_; }

  scoped_refptr<MockWiFi> wifi() { return wifi_; }

 private:
  MockMetrics metrics_;
  MockControl control_interface_;
  EventDispatcherForTest dispatcher_;
  MockManager manager_;

  scoped_refptr<MockWiFi> wifi_;
  std::unique_ptr<WiFiCQM> wifi_cqm_;
};

TEST_F(WiFiCQMTest, TriggerFwDump) {
  ScopedMockLog log;

  ScopeLogger::GetInstance()->EnableScopesByName("wifi");
  ScopeLogger::GetInstance()->set_verbose_level(3);

  EXPECT_CALL(log, Log(_, _, HasSubstr("Triggering FW dump")));
  EXPECT_CALL(log, Log(_, _, HasSubstr("FW dump trigger succeeded")));
  TriggerFwDump();
  EXPECT_EQ(FwDumpCount(), 1);

  Mock::VerifyAndClearExpectations(&log);

  TriggerFwDump();
  // No new FW dump should be triggered in cool down period, so this should
  // still be one.
  EXPECT_EQ(FwDumpCount(), 1);
  ScopeLogger::GetInstance()->set_verbose_level(0);
  ScopeLogger::GetInstance()->EnableScopesByName("-wifi");
}

TEST_F(WiFiCQMTest, OnCQMNotificationBeaconLoss) {
  NotifyCqmMessage msg;

  ScopedMockLog log;
  ScopeLogger::GetInstance()->EnableScopesByName("wifi");
  ScopeLogger::GetInstance()->set_verbose_level(3);

  NetlinkPacket packet(kCQMBeaconLossNLMsg, sizeof(kCQMBeaconLossNLMsg));
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());
  const Nl80211Message& nl80211_msg =
      *reinterpret_cast<const Nl80211Message*>(&msg);

  EXPECT_CALL(log, Log(_, _, HasSubstr("Beacon loss observed")));
  EXPECT_CALL(*metrics(), SendEnumToUMA(Metrics::kMetricWiFiCQMNotification,
                                        Metrics::kWiFiCQMBeaconLoss, _));
  EXPECT_CALL(*wifi(), EmitStationInfoRequestEvent(
                           WiFiLinkStatistics::Trigger::kCQMBeaconLoss))
      .Times(1);
  OnCQMNotify(nl80211_msg);

  Mock::VerifyAndClearExpectations(wifi().get());
  Mock::VerifyAndClearExpectations(&log);

  EXPECT_CALL(*metrics(), SendEnumToUMA(Metrics::kMetricWiFiCQMNotification,
                                        Metrics::kWiFiCQMBeaconLoss, _));
  EXPECT_CALL(*wifi(), EmitStationInfoRequestEvent(
                           WiFiLinkStatistics::Trigger::kCQMBeaconLoss))
      .Times(1);
  OnCQMNotify(nl80211_msg);
  ScopeLogger::GetInstance()->set_verbose_level(0);
  ScopeLogger::GetInstance()->EnableScopesByName("-wifi");
}

TEST_F(WiFiCQMTest, OnCQMNotificationLowRssiLevelBreach) {
  NotifyCqmMessage msg;
  ScopedMockLog log;
  ScopeLogger::GetInstance()->EnableScopesByName("wifi");
  ScopeLogger::GetInstance()->set_verbose_level(3);
  NetlinkPacket packet(kCQMRssiLowNLMsg, sizeof(kCQMRssiLowNLMsg));
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());
  const Nl80211Message& nl80211_msg =
      *reinterpret_cast<const Nl80211Message*>(&msg);
  EXPECT_CALL(*wifi(), EmitStationInfoRequestEvent(
                           WiFiLinkStatistics::Trigger::kCQMRSSILow))
      .Times(1);
  OnCQMNotify(nl80211_msg);
  ScopeLogger::GetInstance()->set_verbose_level(0);
  ScopeLogger::GetInstance()->EnableScopesByName("-wifi");
}

TEST_F(WiFiCQMTest, OnCQMNotificationHighRssiLevelBreach) {
  NotifyCqmMessage msg;
  ScopedMockLog log;
  ScopeLogger::GetInstance()->EnableScopesByName("wifi");
  ScopeLogger::GetInstance()->set_verbose_level(3);
  NetlinkPacket packet(kCQMRssiHighNLMsg, sizeof(kCQMRssiHighNLMsg));
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());
  const Nl80211Message& nl80211_msg =
      *reinterpret_cast<const Nl80211Message*>(&msg);
  EXPECT_CALL(*wifi(), EmitStationInfoRequestEvent(
                           WiFiLinkStatistics::Trigger::kCQMRSSIHigh))
      .Times(1);
  OnCQMNotify(nl80211_msg);
  ScopeLogger::GetInstance()->set_verbose_level(0);
  ScopeLogger::GetInstance()->EnableScopesByName("-wifi");
}

TEST_F(WiFiCQMTest, OnCQMNotificationPacketLoss) {
  NotifyCqmMessage msg;

  ScopedMockLog log;
  ScopeLogger::GetInstance()->EnableScopesByName("wifi");
  ScopeLogger::GetInstance()->set_verbose_level(3);

  NetlinkPacket packet(kCQMPacketLossNLMsg, sizeof(kCQMPacketLossNLMsg));
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());
  const Nl80211Message& nl80211_msg =
      *reinterpret_cast<const Nl80211Message*>(&msg);

  EXPECT_CALL(log, Log(_, _, HasSubstr("Packet loss event received")));
  EXPECT_CALL(*metrics(), SendEnumToUMA(Metrics::kMetricWiFiCQMNotification,
                                        Metrics::kWiFiCQMPacketLoss, _));
  EXPECT_CALL(*wifi(), EmitStationInfoRequestEvent(
                           WiFiLinkStatistics::Trigger::kCQMPacketLoss))
      .Times(1);
  OnCQMNotify(nl80211_msg);

  Mock::VerifyAndClearExpectations(wifi().get());
  Mock::VerifyAndClearExpectations(&log);

  EXPECT_CALL(*metrics(), SendEnumToUMA(Metrics::kMetricWiFiCQMNotification,
                                        Metrics::kWiFiCQMPacketLoss, _));
  EXPECT_CALL(*wifi(), EmitStationInfoRequestEvent(
                           WiFiLinkStatistics::Trigger::kCQMPacketLoss))
      .Times(1);
  OnCQMNotify(nl80211_msg);
  ScopeLogger::GetInstance()->set_verbose_level(0);
  ScopeLogger::GetInstance()->EnableScopesByName("-wifi");
}

}  // namespace shill
