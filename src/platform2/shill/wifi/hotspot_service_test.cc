// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/hotspot_service.h"

#include <memory>
#include <string>
#include <vector>

#include <base/memory/ref_counted.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/test/mock_callback.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/mock_control.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/store/key_value_store.h"
#include "shill/supplicant/wpa_supplicant.h"
#include "shill/test_event_dispatcher.h"
#include "shill/wifi/mock_local_device.h"
#include "shill/wifi/wifi_security.h"

using ::testing::_;
using ::testing::NiceMock;
using ::testing::StrictMock;

namespace shill {

namespace {
constexpr char kHexSSID[] = "74657374";  // Hex encode for "test"
constexpr char kPassphrase[] = "passphrase";
constexpr int kFrequency = 2437;
}  // namespace

class HotspotServiceTest : public testing::Test {
 public:
  HotspotServiceTest()
      : manager_(&control_interface_, &dispatcher_, &metrics_) {
    device_ =
        new NiceMock<MockLocalDevice>(&manager_, LocalDevice::IfaceType::kAP,
                                      "ap0", "00:00:00:00:00:00", 0, cb.Get());
  }
  ~HotspotServiceTest() override = default;

  std::unique_ptr<HotspotService> CreateHotspotService(
      const WiFiSecurity security) {
    std::unique_ptr<HotspotService> service = std::make_unique<HotspotService>(
        device_, kHexSSID, kPassphrase, security, kFrequency);
    return service;
  }

 private:
  StrictMock<base::MockRepeatingCallback<void(LocalDevice::DeviceEvent,
                                              const LocalDevice*)>>
      cb;

  NiceMock<MockControl> control_interface_;
  EventDispatcherForTest dispatcher_;
  NiceMock<MockMetrics> metrics_;
  NiceMock<MockManager> manager_;
  scoped_refptr<MockLocalDevice> device_;
};

MATCHER_P(HasHotspotArgs, hex_ssid, "") {
  std::vector<uint8_t> ssid_bytes;
  base::HexStringToBytes(hex_ssid, &ssid_bytes);

  return arg.template Contains<uint32_t>(WPASupplicant::kNetworkPropertyMode) &&
         arg.template Get<uint32_t>(WPASupplicant::kNetworkPropertyMode) ==
             WPASupplicant::kNetworkModeAccessPointInt &&
         arg.template Contains<std::vector<uint8_t>>(
             WPASupplicant::kNetworkPropertySSID) &&
         arg.template Get<std::vector<uint8_t>>(
             WPASupplicant::kNetworkPropertySSID) == ssid_bytes;
}

MATCHER_P(HasPskArgs, passphrase, "") {
  return arg.template Contains<std::string>(
             WPASupplicant::kPropertySecurityProtocol) &&
         arg.template Contains<std::string>(
             WPASupplicant::kNetworkPropertyEapKeyManagement) &&
         arg.template Contains<std::string>(
             WPASupplicant::kPropertyPreSharedKey) &&
         arg.template Get<std::string>(WPASupplicant::kPropertyPreSharedKey) ==
             passphrase;
}

MATCHER_P(HasKeyMgmtArgs, key_mgmt, "") {
  return arg.template Contains<std::string>(
             WPASupplicant::kNetworkPropertyEapKeyManagement) &&
         arg.template Get<std::string>(
             WPASupplicant::kNetworkPropertyEapKeyManagement) == key_mgmt;
}

MATCHER_P(HasPskProtoArgs, psk_proto, "") {
  return arg.template Contains<std::string>(
             WPASupplicant::kPropertySecurityProtocol) &&
         arg.template Get<std::string>(
             WPASupplicant::kPropertySecurityProtocol) == psk_proto;
}

MATCHER_P(HasPmfArgs, pmf, "") {
  return arg.template Contains<uint32_t>(
             WPASupplicant::kNetworkPropertyIeee80211w) &&
         arg.template Get<uint32_t>(
             WPASupplicant::kNetworkPropertyIeee80211w) == pmf;
}

MATCHER(HasCipherCCMP, "") {
  return arg.template Contains<std::string>(
             WPASupplicant::kNetworkCipherPairwise) &&
         arg.template Get<std::string>(WPASupplicant::kNetworkCipherPairwise) ==
             WPASupplicant::kNetworkCipherSuiteCCMP &&
         arg.template Contains<std::string>(
             WPASupplicant::kNetworkCipherGroup) &&
         arg.template Get<std::string>(WPASupplicant::kNetworkCipherGroup) ==
             WPASupplicant::kNetworkCipherSuiteCCMP;
}

MATCHER_P(HasFrequency, freq, "") {
  return arg.template Contains<int>(WPASupplicant::kNetworkPropertyFrequency) &&
         arg.template Get<int>(WPASupplicant::kNetworkPropertyFrequency) ==
             freq;
}

TEST_F(HotspotServiceTest, GetSupplicantConfigWEP) {
  // Get configuration with non PSK or OPEN mode should result in an empty
  // dictionary.
  auto service = CreateHotspotService(WiFiSecurity::kWep);
  KeyValueStore params = service->GetSupplicantConfigurationParameters();
  EXPECT_TRUE(params.IsEmpty());
}

TEST_F(HotspotServiceTest, GetSupplicantConfigOpen) {
  auto service = CreateHotspotService(WiFiSecurity::kNone);
  KeyValueStore params = service->GetSupplicantConfigurationParameters();
  EXPECT_THAT(params, HasHotspotArgs(kHexSSID));
  EXPECT_THAT(params, HasKeyMgmtArgs(WPASupplicant::kKeyManagementNone));
  EXPECT_THAT(params, HasFrequency(kFrequency));
}

TEST_F(HotspotServiceTest, GetSupplicantConfigWpa) {
  // Hotspot does not support WPA.
  auto service = CreateHotspotService(WiFiSecurity::kWpa);
  KeyValueStore params = service->GetSupplicantConfigurationParameters();
  EXPECT_TRUE(params.IsEmpty());
}

TEST_F(HotspotServiceTest, GetSupplicantConfigWpa2) {
  auto service = CreateHotspotService(WiFiSecurity::kWpa2);
  KeyValueStore params = service->GetSupplicantConfigurationParameters();
  EXPECT_THAT(params, HasHotspotArgs(kHexSSID));
  EXPECT_THAT(params, HasPskArgs(std::string(kPassphrase)));
  EXPECT_THAT(params, HasPskProtoArgs(WPASupplicant::kSecurityModeRSN));
  EXPECT_THAT(params, HasKeyMgmtArgs(WPASupplicant::kKeyManagementWPAPSK));
  EXPECT_THAT(params, HasPmfArgs(WPASupplicant::kNetworkIeee80211wEnabled));
  EXPECT_THAT(params, HasCipherCCMP());
  EXPECT_THAT(params, HasFrequency(kFrequency));
}

TEST_F(HotspotServiceTest, GetSupplicantConfigWpaWpa2) {
  // Hotspot does not support WPAWPA2.
  auto service = CreateHotspotService(WiFiSecurity::kWpaWpa2);
  KeyValueStore params = service->GetSupplicantConfigurationParameters();
  EXPECT_TRUE(params.IsEmpty());
}

TEST_F(HotspotServiceTest, GetSupplicantConfigWpa3) {
  auto service = CreateHotspotService(WiFiSecurity::kWpa3);
  KeyValueStore params = service->GetSupplicantConfigurationParameters();
  EXPECT_THAT(params, HasHotspotArgs(kHexSSID));
  EXPECT_THAT(params, HasPskArgs(std::string(kPassphrase)));
  EXPECT_THAT(params, HasPskProtoArgs(WPASupplicant::kSecurityModeRSN));
  EXPECT_THAT(params, HasKeyMgmtArgs(WPASupplicant::kKeyManagementSAE));
  EXPECT_THAT(params, HasPmfArgs(WPASupplicant::kNetworkIeee80211wRequired));
  EXPECT_THAT(params, HasCipherCCMP());
  EXPECT_THAT(params, HasFrequency(kFrequency));
}

TEST_F(HotspotServiceTest, GetSupplicantConfigWpa2Wpa3) {
  auto service = CreateHotspotService(WiFiSecurity::kWpa2Wpa3);
  KeyValueStore params = service->GetSupplicantConfigurationParameters();
  EXPECT_THAT(params, HasHotspotArgs(kHexSSID));
  EXPECT_THAT(params, HasPskArgs(std::string(kPassphrase)));
  EXPECT_THAT(params, HasPskProtoArgs(WPASupplicant::kSecurityModeRSN));
  std::string key_mgmt =
      base::StringPrintf("%s %s", WPASupplicant::kKeyManagementWPAPSK,
                         WPASupplicant::kKeyManagementSAE);
  EXPECT_THAT(params, HasKeyMgmtArgs(key_mgmt));
  EXPECT_THAT(params, HasPmfArgs(WPASupplicant::kNetworkIeee80211wRequired));
  EXPECT_THAT(params, HasCipherCCMP());
  EXPECT_THAT(params, HasFrequency(kFrequency));
}

}  // namespace shill
