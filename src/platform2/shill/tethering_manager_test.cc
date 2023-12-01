// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/tethering_manager.h"

#include <sys/socket.h>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/containers/contains.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <base/test/mock_callback.h>
#include <chromeos/dbus/shill/dbus-constants.h>
#include <chromeos/patchpanel/dbus/fake_client.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/cellular/cellular_service_provider.h"
#include "shill/cellular/mock_cellular.h"
#include "shill/cellular/mock_cellular_service.h"
#include "shill/cellular/mock_cellular_service_provider.h"
#include "shill/cellular/mock_modem_info.h"
#include "shill/error.h"
#include "shill/ethernet/mock_ethernet_provider.h"
#include "shill/manager.h"
#include "shill/mock_control.h"
#include "shill/mock_device.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_profile.h"
#include "shill/mock_service.h"
#include "shill/network/mock_network.h"
#include "shill/store/fake_store.h"
#include "shill/store/property_store.h"
#include "shill/technology.h"
#include "shill/test_event_dispatcher.h"
#include "shill/upstart/mock_upstart.h"
#include "shill/wifi/local_device.h"
#include "shill/wifi/local_service.h"
#include "shill/wifi/mock_hotspot_device.h"
#include "shill/wifi/mock_wake_on_wifi.h"
#include "shill/wifi/mock_wifi.h"
#include "shill/wifi/mock_wifi_phy.h"
#include "shill/wifi/mock_wifi_provider.h"

using testing::_;
using testing::DoAll;
using testing::DoDefault;
using testing::Eq;
using testing::Invoke;
using testing::Mock;
using testing::NiceMock;
using testing::Not;
using testing::Return;
using testing::StrictMock;
using testing::Test;
using testing::WithArg;

namespace shill {
namespace {

// Fake profile identities
constexpr char kDefaultProfile[] = "default";
constexpr char kUserProfile[] = "~user/profile";
constexpr uint32_t kPhyIndex = 5678;
constexpr int kTestInterfaceIndex = 3;
constexpr char kTestInterfaceName[] = "wwan0";

// The value below is "testAP-0000" in hex;
constexpr char kTestAPHexSSID[] = "7465737441502d30303030";
constexpr char kTestPassword[] = "user_password";

// WiFi frequency constants
constexpr uint32_t kLBStartFreq = 2412;
constexpr uint32_t kChan11Freq = 2462;
constexpr uint32_t kHBStartFreq = 5160;
constexpr uint32_t kHBEndFreq = 5980;

bool GetConfigMAR(const KeyValueStore& caps) {
  return caps.Get<bool>(kTetheringConfMARProperty);
}
bool GetConfigAutoDisable(const KeyValueStore& caps) {
  return caps.Get<bool>(kTetheringConfAutoDisableProperty);
}
std::string GetConfigSSID(const KeyValueStore& caps) {
  return caps.Get<std::string>(kTetheringConfSSIDProperty);
}
std::string GetConfigPassphrase(const KeyValueStore& caps) {
  return caps.Get<std::string>(kTetheringConfPassphraseProperty);
}
std::string GetConfigSecurity(const KeyValueStore& caps) {
  return caps.Get<std::string>(kTetheringConfSecurityProperty);
}
std::string GetConfigBand(const KeyValueStore& caps) {
  return caps.Get<std::string>(kTetheringConfBandProperty);
}
std::string GetConfigUpstream(const KeyValueStore& caps) {
  return caps.Get<std::string>(kTetheringConfUpstreamTechProperty);
}
void SetConfigMAR(KeyValueStore& caps, bool value) {
  caps.Set<bool>(kTetheringConfMARProperty, value);
}
void SetConfigAutoDisable(KeyValueStore& caps, bool value) {
  caps.Set<bool>(kTetheringConfAutoDisableProperty, value);
}
void SetConfigSSID(KeyValueStore& caps, const std::string& value) {
  caps.Set<std::string>(kTetheringConfSSIDProperty, value);
}
void SetConfigPassphrase(KeyValueStore& caps, const std::string& value) {
  caps.Set<std::string>(kTetheringConfPassphraseProperty, value);
}
void SetConfigSecurity(KeyValueStore& caps, const std::string& value) {
  caps.Set<std::string>(kTetheringConfSecurityProperty, value);
}
void SetConfigBand(KeyValueStore& caps, const std::string& value) {
  caps.Set<std::string>(kTetheringConfBandProperty, value);
}
void SetConfigUpstream(KeyValueStore& caps, const std::string& value) {
  caps.Set<std::string>(kTetheringConfUpstreamTechProperty, value);
}

base::ScopedTempDir MakeTempDir() {
  base::ScopedTempDir temp_dir;
  EXPECT_TRUE(temp_dir.CreateUniqueTempDir());
  return temp_dir;
}

class MockPatchpanelClient : public patchpanel::FakeClient {
 public:
  MockPatchpanelClient() = default;
  ~MockPatchpanelClient() = default;

  MOCK_METHOD(bool,
              CreateTetheredNetwork,
              (const std::string&,
               const std::string&,
               const std::optional<DHCPOptions>&,
               const std::optional<int>& mtu,
               patchpanel::Client::CreateTetheredNetworkCallback),
              (override));
};

base::ScopedFD MakeFd() {
  return base::ScopedFD(socket(AF_INET, SOCK_DGRAM, 0));
}

}  // namespace

class TetheringManagerTest : public testing::Test {
 public:
  TetheringManagerTest()
      : temp_dir_(MakeTempDir()),
        path_(temp_dir_.GetPath().value()),
        manager_(
            &control_interface_, &dispatcher_, &metrics_, path_, path_, path_),
        modem_info_(&control_interface_, &manager_),
        tethering_manager_(manager_.tethering_manager()),
        wifi_provider_(new NiceMock<MockWiFiProvider>(&manager_)),
        ethernet_provider_(new NiceMock<MockEthernetProvider>()),
        cellular_service_provider_(
            new NiceMock<MockCellularServiceProvider>(&manager_)),
        upstart_(new NiceMock<MockUpstart>(&control_interface_)),
        hotspot_device_(new NiceMock<MockHotspotDevice>(
            &manager_, "wlan0", "ap0", "", 0, event_cb_.Get())),
        network_(new MockNetwork(
            kTestInterfaceIndex, kTestInterfaceName, Technology::kCellular)),
        service_(new MockService(&manager_)),
        wifi_phy_(hotspot_device_->phy_index()) {
    // Replace the Manager's WiFi provider with a mock.
    manager_.wifi_provider_.reset(wifi_provider_);
    // Replace the Manager's Ethernet provider with a mock.
    manager_.ethernet_provider_.reset(ethernet_provider_);
    // Replace the Manager's Cellular provider with a mock.
    manager_.cellular_service_provider_.reset(cellular_service_provider_);
    // Update the Manager's map from technology to provider.
    manager_.UpdateProviderMapping();
    // Replace the Manager's upstart instance with a mock.
    manager_.upstart_.reset(upstart_);
    // Replace the Manager's patchpanel DBus client with a mock.
    auto patchpanel = std::make_unique<MockPatchpanelClient>();
    patchpanel_ = patchpanel.get();
    manager_.set_patchpanel_client_for_testing(std::move(patchpanel));

    ON_CALL(manager_, cellular_service_provider())
        .WillByDefault(Return(cellular_service_provider_));
    cellular_profile_ = new NiceMock<MockProfile>(&manager_);
    cellular_service_provider_->set_profile_for_testing(cellular_profile_);
    ON_CALL(manager_, modem_info()).WillByDefault(Return(&modem_info_));
    ON_CALL(*wifi_provider_, CreateHotspotDevice(_, _, _, _))
        .WillByDefault(Return(hotspot_device_));
    ON_CALL(*hotspot_device_.get(), ConfigureService(_))
        .WillByDefault(Return(true));
    ON_CALL(*hotspot_device_.get(), DeconfigureService())
        .WillByDefault(Return(true));
    ON_CALL(*hotspot_device_.get(), IsServiceUp()).WillByDefault(Return(true));
    ON_CALL(*cellular_service_provider_, AcquireTetheringNetwork(_))
        .WillByDefault(Return());
    ON_CALL(*cellular_service_provider_, ReleaseTetheringNetwork(_, _))
        .WillByDefault(Return());
    ON_CALL(*network_, HasInternetConnectivity()).WillByDefault(Return(true));
    ON_CALL(*network_, IsConnected()).WillByDefault(Return(true));
    ON_CALL(*wifi_provider_, GetPhyAtIndex(hotspot_device_->phy_index()))
        .WillByDefault(Return(&wifi_phy_));
    wifi_phy_.SetFrequencies(
        {{0, {{.value = 2412}, {.value = 2432}, {.value = 2437}}},
         {1, {{.value = 5220}, {.value = 5240}}}});
  }
  ~TetheringManagerTest() override = default;

  scoped_refptr<MockCellular> MakeCellular(const std::string& link_name,
                                           const std::string& address,
                                           int interface_index) {
    return new NiceMock<MockCellular>(&manager_, link_name, address,
                                      interface_index, "", RpcIdentifier(""));
  }

  Error::Type TestCreateProfile(Manager* manager, const std::string& name) {
    Error error;
    std::string path;
    manager->CreateProfile(name, &path, &error);
    return error.type();
  }

  Error::Type TestPushProfile(Manager* manager, const std::string& name) {
    Error error;
    std::string path;
    manager->PushProfile(name, &path, &error);
    return error.type();
  }

  Error::Type TestPopProfile(Manager* manager, const std::string& name) {
    Error error;
    manager->PopProfile(name, &error);
    return error.type();
  }

  void SetAllowed(TetheringManager* tethering_manager, bool allowed) {
    Error error;
    PropertyStore store;
    tethering_manager->InitPropertyStore(&store);
    store.SetBoolProperty(kTetheringAllowedProperty, allowed, &error);
    EXPECT_TRUE(error.IsSuccess());
  }

  KeyValueStore GetCapabilities(TetheringManager* tethering_manager) {
    Error error;
    KeyValueStore caps = tethering_manager->GetCapabilities(&error);
    EXPECT_TRUE(error.IsSuccess());
    return caps;
  }

  bool SetAndPersistConfig(TetheringManager* tethering_manager,
                           const KeyValueStore& config) {
    Error error;
    bool is_success = tethering_manager->SetAndPersistConfig(config, &error);
    EXPECT_EQ(is_success, error.IsSuccess());
    return is_success;
  }

  void SetEnabled(TetheringManager* tethering_manager, bool enabled) {
    tethering_manager->SetEnabled(enabled, result_cb_.Get());
  }

  void VerifyResult(TetheringManager::SetEnabledResult expected_result) {
    EXPECT_CALL(result_cb_, Run(expected_result));
    DispatchPendingEvents();
    Mock::VerifyAndClearExpectations(&result_cb_);
    EXPECT_TRUE(GetStartTimer(tethering_manager_).IsCancelled());
  }

  void SetEnabledVerifyResult(
      TetheringManager* tethering_manager,
      bool enabled,
      TetheringManager::SetEnabledResult expected_result) {
    SetEnabled(tethering_manager, enabled);
    if (enabled) {
      ON_CALL(*patchpanel_, CreateTetheredNetwork("ap0", "wwan0", _, _, _))
          .WillByDefault(Return(true));
      // Send upstream downstream ready events.
      DownStreamDeviceEvent(tethering_manager,
                            LocalDevice::DeviceEvent::kServiceUp,
                            hotspot_device_.get());
      OnUpstreamNetworkAcquired(tethering_manager_,
                                TetheringManager::SetEnabledResult::kSuccess);
      OnDownstreamNetworkReady(tethering_manager_, MakeFd());
    } else {
      // Send upstream tear down event
      OnUpstreamNetworkReleased(tethering_manager_, true);
    }
    VerifyResult(expected_result);
  }

  KeyValueStore GetConfig(TetheringManager* tethering_manager) {
    Error error;
    KeyValueStore caps = tethering_manager->GetConfig(&error);
    EXPECT_TRUE(error.IsSuccess());
    return caps;
  }

  bool SaveConfig(TetheringManager* tethering_manager,
                  StoreInterface* storage) {
    return tethering_manager->Save(storage);
  }

  bool FromProperties(TetheringManager* tethering_manager,
                      const KeyValueStore& config) {
    return tethering_manager->FromProperties(config);
  }

  KeyValueStore VerifyDefaultTetheringConfig(
      TetheringManager* tethering_manager) {
    KeyValueStore caps = GetConfig(tethering_manager);
    EXPECT_TRUE(GetConfigMAR(caps));
    EXPECT_TRUE(tethering_manager->stable_mac_addr_.is_set());
    EXPECT_TRUE(GetConfigAutoDisable(caps));
    std::string ssid = GetConfigSSID(caps);
    EXPECT_FALSE(ssid.empty());
    EXPECT_TRUE(std::all_of(ssid.begin(), ssid.end(), ::isxdigit));
    std::string passphrase = GetConfigPassphrase(caps);
    EXPECT_FALSE(passphrase.empty());
    EXPECT_TRUE(std::all_of(passphrase.begin(), passphrase.end(), ::isxdigit));
    EXPECT_EQ(kSecurityWpa2, GetConfigSecurity(caps));
    EXPECT_EQ(GetConfigBand(caps), kBandAll);
    EXPECT_TRUE(caps.Contains<std::string>(kTetheringConfUpstreamTechProperty));
    return caps;
  }

  KeyValueStore GenerateFakeConfig(const std::string& ssid,
                                   const std::string passphrase) {
    KeyValueStore config;
    SetConfigMAR(config, false);
    SetConfigAutoDisable(config, false);
    SetConfigSSID(config, ssid);
    SetConfigPassphrase(config, passphrase);
    SetConfigSecurity(config, kSecurityWpa3);
    SetConfigBand(config, kBand2GHz);
    SetConfigUpstream(config, kTypeCellular);
    return config;
  }

  void DispatchPendingEvents() { dispatcher_.DispatchPendingEvents(); }

  void TetheringPrerequisite(TetheringManager* tethering_manager) {
    SetAllowed(tethering_manager, true);

    ASSERT_EQ(Error::kSuccess, TestCreateProfile(&manager_, kDefaultProfile));
    EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager_, kDefaultProfile));
    ASSERT_TRUE(base::CreateDirectory(temp_dir_.GetPath().Append("user")));
    ASSERT_EQ(Error::kSuccess, TestCreateProfile(&manager_, kUserProfile));
    EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager_, kUserProfile));
  }

  void DownStreamDeviceEvent(TetheringManager* tethering_manager,
                             LocalDevice::DeviceEvent event,
                             LocalDevice* device) {
    tethering_manager->OnDownstreamDeviceEvent(event, device);
  }

  TetheringManager::TetheringState TetheringState(
      TetheringManager* tethering_manager) {
    return tethering_manager->state_;
  }

  std::string StopReason(TetheringManager* tethering_manager) {
    return TetheringManager::StopReasonToString(
        tethering_manager->stop_reason_);
  }

  void CheckTetheringStopping(TetheringManager* tethering_manager,
                              const char* reason) {
    EXPECT_EQ(TetheringState(tethering_manager),
              TetheringManager::TetheringState::kTetheringStopping);
    EXPECT_EQ(StopReason(tethering_manager), reason);
  }

  void CheckTetheringIdle(TetheringManager* tethering_manager,
                          const char* reason) {
    EXPECT_EQ(tethering_manager->hotspot_dev_, nullptr);
    EXPECT_EQ(TetheringState(tethering_manager),
              TetheringManager::TetheringState::kTetheringIdle);
    auto status = GetStatus(tethering_manager);
    EXPECT_EQ(status.Get<std::string>(kTetheringStatusIdleReasonProperty),
              reason);
    EXPECT_TRUE(GetStartTimer(tethering_manager_).IsCancelled());
    EXPECT_TRUE(GetStopTimer(tethering_manager_).IsCancelled());
  }

  KeyValueStore GetStatus(TetheringManager* tethering_manager) {
    return tethering_manager->GetStatus();
  }

  void OnStartingTetheringTimeout(TetheringManager* tethering_manager) {
    tethering_manager->OnStartingTetheringTimeout();
  }

  void OnStoppingTetheringTimeout(TetheringManager* tethering_manager) {
    tethering_manager->OnStoppingTetheringTimeout();
  }

  const base::CancelableOnceClosure& GetStartTimer(
      TetheringManager* tethering_manager) {
    return tethering_manager->start_timer_callback_;
  }

  const base::CancelableOnceClosure& GetStopTimer(
      TetheringManager* tethering_manager) {
    return tethering_manager->stop_timer_callback_;
  }

  const base::CancelableOnceClosure& GetInactiveTimer(
      TetheringManager* tethering_manager) {
    return tethering_manager->inactive_timer_callback_;
  }

  void AddServiceToCellularProvider(CellularServiceRefPtr service) {
    cellular_service_provider_->AddService(service);
  }

  void OnDownstreamNetworkReady(TetheringManager* tethering_manager,
                                base::ScopedFD fd) {
    tethering_manager->OnDownstreamNetworkReady(std::move(fd));
  }

  void OnUpstreamNetworkAcquired(TetheringManager* tethering_manager,
                                 TetheringManager::SetEnabledResult result) {
    tethering_manager->OnUpstreamNetworkAcquired(result, network_.get(),
                                                 service_.get());
  }

  void OnUpstreamNetworkReleased(TetheringManager* tethering_manager,
                                 bool success) {
    tethering_manager->OnUpstreamNetworkReleased(success);
  }

  void OnUpstreamNetworkStopped(TetheringManager* tethering_manager) {
    tethering_manager->OnNetworkStopped(kTestInterfaceIndex, false);
  }

  void OnUpstreamNetworkDestroyed(TetheringManager* tethering_manager) {
    tethering_manager->OnNetworkDestroyed(kTestInterfaceIndex);
  }

  void OnUpstreamNetworkValidationResult(TetheringManager* tethering_manager) {
    PortalDetector::Result result;
    tethering_manager->OnNetworkValidationResult(kTestInterfaceIndex, result);
  }

 protected:
  StrictMock<base::MockRepeatingCallback<void(LocalDevice::DeviceEvent,
                                              const LocalDevice*)>>
      event_cb_;
  StrictMock<base::MockOnceCallback<void(TetheringManager::SetEnabledResult)>>
      result_cb_;

  NiceMock<MockControl> control_interface_;
  EventDispatcherForTest dispatcher_;
  NiceMock<MockMetrics> metrics_;
  base::ScopedTempDir temp_dir_;
  std::string path_;
  MockManager manager_;
  MockModemInfo modem_info_;
  MockPatchpanelClient* patchpanel_;
  TetheringManager* tethering_manager_;
  MockWiFiProvider* wifi_provider_;
  MockEthernetProvider* ethernet_provider_;
  scoped_refptr<NiceMock<MockProfile>> cellular_profile_;
  MockCellularServiceProvider* cellular_service_provider_;
  MockUpstart* upstart_;
  scoped_refptr<MockHotspotDevice> hotspot_device_;
  std::unique_ptr<MockNetwork> network_;
  scoped_refptr<MockService> service_;
  MockWiFiPhy wifi_phy_;
};

TEST_F(TetheringManagerTest, GetTetheringCapabilities) {
  std::unique_ptr<NiceMock<MockWiFiPhy>> phy(
      new NiceMock<MockWiFiPhy>(kPhyIndex));
  const std::vector<const WiFiPhy*> phys = {phy.get()};
  ON_CALL(*wifi_provider_, GetPhys()).WillByDefault(Return(phys));
  ON_CALL(*phy, SupportAPMode()).WillByDefault(Return(true));
  ON_CALL(*phy, SupportAPSTAConcurrency()).WillByDefault(Return(true));
  EXPECT_CALL(*cellular_service_provider_, HardwareSupportsTethering())
      .WillOnce(Return(true));
  SetAllowed(tethering_manager_, true);
  KeyValueStore caps = GetCapabilities(tethering_manager_);

  auto upstream_technologies =
      caps.Get<std::vector<std::string>>(kTetheringCapUpstreamProperty);
  EXPECT_FALSE(upstream_technologies.empty());
  EXPECT_TRUE(base::Contains(upstream_technologies, kTypeEthernet));
  EXPECT_TRUE(base::Contains(upstream_technologies, kTypeCellular));
  EXPECT_FALSE(base::Contains(upstream_technologies, kTypeWifi));

  auto downstream_technologies =
      caps.Get<std::vector<std::string>>(kTetheringCapDownstreamProperty);
  EXPECT_FALSE(downstream_technologies.empty());
  EXPECT_FALSE(base::Contains(downstream_technologies, kTypeEthernet));
  EXPECT_FALSE(base::Contains(downstream_technologies, kTypeCellular));
  EXPECT_TRUE(base::Contains(downstream_technologies, kTypeWifi));

  std::vector<std::string> wifi_security =
      caps.Get<std::vector<std::string>>(kTetheringCapSecurityProperty);
  EXPECT_FALSE(wifi_security.empty());
}

TEST_F(TetheringManagerTest, GetTetheringCapabilitiesWithoutWiFi) {
  const std::vector<DeviceRefPtr> devices;
  ON_CALL(manager_, FilterByTechnology(Technology::kWiFi))
      .WillByDefault(Return(devices));
  EXPECT_CALL(*cellular_service_provider_, HardwareSupportsTethering())
      .WillOnce(Return(true));
  SetAllowed(tethering_manager_, true);

  KeyValueStore caps = GetCapabilities(tethering_manager_);

  auto upstream_technologies =
      caps.Get<std::vector<std::string>>(kTetheringCapUpstreamProperty);
  EXPECT_FALSE(upstream_technologies.empty());
  EXPECT_TRUE(base::Contains(upstream_technologies, kTypeEthernet));
  EXPECT_TRUE(base::Contains(upstream_technologies, kTypeCellular));
  EXPECT_FALSE(base::Contains(upstream_technologies, kTypeWifi));

  auto downstream_technologies =
      caps.Get<std::vector<std::string>>(kTetheringCapDownstreamProperty);
  EXPECT_TRUE(downstream_technologies.empty());

  EXPECT_FALSE(
      caps.Contains<std::vector<std::string>>(kTetheringCapSecurityProperty));
}

TEST_F(TetheringManagerTest, GetTetheringCapabilitiesWithoutCellular) {
  std::unique_ptr<NiceMock<MockWiFiPhy>> phy(
      new NiceMock<MockWiFiPhy>(kPhyIndex));
  const std::vector<const WiFiPhy*> phys = {phy.get()};
  ON_CALL(*wifi_provider_, GetPhys()).WillByDefault(Return(phys));
  ON_CALL(*phy, SupportAPMode()).WillByDefault(Return(true));
  ON_CALL(*phy, SupportAPSTAConcurrency()).WillByDefault(Return(true));
  EXPECT_CALL(*cellular_service_provider_, HardwareSupportsTethering())
      .WillOnce(Return(false));
  SetAllowed(tethering_manager_, true);

  KeyValueStore caps = GetCapabilities(tethering_manager_);

  auto upstream_technologies =
      caps.Get<std::vector<std::string>>(kTetheringCapUpstreamProperty);
  EXPECT_FALSE(upstream_technologies.empty());
  EXPECT_TRUE(base::Contains(upstream_technologies, kTypeEthernet));
  EXPECT_FALSE(base::Contains(upstream_technologies, kTypeCellular));
  EXPECT_FALSE(base::Contains(upstream_technologies, kTypeWifi));

  auto downstream_technologies =
      caps.Get<std::vector<std::string>>(kTetheringCapDownstreamProperty);
  EXPECT_FALSE(downstream_technologies.empty());
  EXPECT_FALSE(base::Contains(downstream_technologies, kTypeEthernet));
  EXPECT_FALSE(base::Contains(downstream_technologies, kTypeCellular));
  EXPECT_TRUE(base::Contains(downstream_technologies, kTypeWifi));

  std::vector<std::string> wifi_security =
      caps.Get<std::vector<std::string>>(kTetheringCapSecurityProperty);
  EXPECT_FALSE(wifi_security.empty());
}

TEST_F(TetheringManagerTest, TetheringConfig) {
  SetAllowed(tethering_manager_, true);

  ASSERT_EQ(Error::kSuccess, TestCreateProfile(&manager_, kDefaultProfile));
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager_, kDefaultProfile));

  // Check default TetheringConfig.
  VerifyDefaultTetheringConfig(tethering_manager_);

  // Fake Tethering configuration.
  KeyValueStore args = GenerateFakeConfig(kTestAPHexSSID, kTestPassword);

  // Block SetAndPersistConfig when no user has logged in.
  EXPECT_FALSE(SetAndPersistConfig(tethering_manager_, args));

  // SetAndPersistConfig succeeds when a user is logged in.
  ASSERT_TRUE(base::CreateDirectory(temp_dir_.GetPath().Append("user")));
  ASSERT_EQ(Error::kSuccess, TestCreateProfile(&manager_, kUserProfile));
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager_, kUserProfile));
  EXPECT_TRUE(SetAndPersistConfig(tethering_manager_, args));

  // Read the configuration and check if it matches.
  KeyValueStore config = GetConfig(tethering_manager_);
  EXPECT_FALSE(GetConfigMAR(config));
  EXPECT_FALSE(GetConfigAutoDisable(config));
  EXPECT_EQ(GetConfigSSID(config), kTestAPHexSSID);
  EXPECT_EQ(GetConfigPassphrase(config), kTestPassword);
  EXPECT_EQ(GetConfigSecurity(config), kSecurityWpa3);
  EXPECT_EQ(GetConfigBand(config), kBand2GHz);
  EXPECT_EQ(GetConfigUpstream(config), kTypeCellular);

  // Log out user and check user's tethering config is not present.
  EXPECT_EQ(Error::kSuccess, TestPopProfile(&manager_, kUserProfile));
  KeyValueStore default_config = GetConfig(tethering_manager_);
  EXPECT_NE(GetConfigSSID(default_config), kTestAPHexSSID);
  EXPECT_NE(GetConfigPassphrase(default_config), kTestPassword);

  // Log in user and check tethering config again.
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager_, kUserProfile));
  config = GetConfig(tethering_manager_);
  EXPECT_FALSE(GetConfigMAR(config));
  EXPECT_FALSE(GetConfigAutoDisable(config));
  EXPECT_EQ(GetConfigSSID(config), kTestAPHexSSID);
  EXPECT_EQ(GetConfigPassphrase(config), kTestPassword);
  EXPECT_EQ(GetConfigSecurity(config), kSecurityWpa3);
  EXPECT_EQ(GetConfigBand(config), kBand2GHz);
  EXPECT_EQ(GetConfigUpstream(config), kTypeCellular);
}

TEST_F(TetheringManagerTest, DefaultConfigCheck) {
  SetAllowed(tethering_manager_, true);
  // SetEnabled proceed to starting state and persist the default config.
  ASSERT_TRUE(base::CreateDirectory(temp_dir_.GetPath().Append("user")));
  ASSERT_EQ(Error::kSuccess, TestCreateProfile(&manager_, kUserProfile));
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager_, kUserProfile));
  KeyValueStore config = GetConfig(tethering_manager_);
  SetEnabled(tethering_manager_, true);
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringStarting);

  // Log out user and check a new SSID and passphrase is generated.
  EXPECT_EQ(Error::kSuccess, TestPopProfile(&manager_, kUserProfile));
  KeyValueStore default_config = GetConfig(tethering_manager_);
  EXPECT_NE(GetConfigSSID(config), GetConfigSSID(default_config));
  EXPECT_NE(GetConfigPassphrase(config), GetConfigPassphrase(default_config));

  // Log in user and check the tethering config matches.
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager_, kUserProfile));
  KeyValueStore new_config = GetConfig(tethering_manager_);
  EXPECT_EQ(GetConfigMAR(config), GetConfigMAR(new_config));
  EXPECT_EQ(GetConfigAutoDisable(config), GetConfigAutoDisable(new_config));
  EXPECT_EQ(GetConfigSSID(config), GetConfigSSID(new_config));
  EXPECT_EQ(GetConfigPassphrase(config), GetConfigPassphrase(new_config));
  EXPECT_EQ(GetConfigBand(config), kBandAll);
  EXPECT_TRUE(
      new_config.Contains<std::string>(kTetheringConfUpstreamTechProperty));
}

TEST_F(TetheringManagerTest, TetheringConfigLoadAndUnload) {
  // Check properties of the default tethering configuration.
  VerifyDefaultTetheringConfig(tethering_manager_);

  // Prepare faked tethering configuration stored for a fake user profile.
  FakeStore store;
  store.SetBool(TetheringManager::kStorageId, kTetheringConfAutoDisableProperty,
                true);
  store.SetBool(TetheringManager::kStorageId, kTetheringConfMARProperty, true);
  MACAddress mac;
  mac.Randomize();
  mac.Save(&store, TetheringManager::kStorageId);
  store.SetString(TetheringManager::kStorageId, kTetheringConfSSIDProperty,
                  kTestAPHexSSID);
  store.SetString(TetheringManager::kStorageId,
                  kTetheringConfPassphraseProperty, kTestPassword);
  store.SetString(TetheringManager::kStorageId, kTetheringConfSecurityProperty,
                  kSecurityWpa3);
  store.SetString(TetheringManager::kStorageId, kTetheringConfBandProperty,
                  kBand5GHz);
  store.SetString(TetheringManager::kStorageId,
                  kTetheringConfUpstreamTechProperty, kTypeCellular);
  scoped_refptr<MockProfile> profile =
      new MockProfile(&manager_, "~user/profile0");
  EXPECT_CALL(*profile, GetConstStorage()).WillRepeatedly(Return(&store));

  // Check faked properties are loaded.
  tethering_manager_->LoadConfigFromProfile(profile);
  KeyValueStore caps = GetConfig(tethering_manager_);
  EXPECT_TRUE(GetConfigMAR(caps));
  EXPECT_EQ(tethering_manager_->stable_mac_addr_, mac);
  EXPECT_TRUE(GetConfigAutoDisable(caps));
  EXPECT_EQ(kTestAPHexSSID, GetConfigSSID(caps));
  EXPECT_EQ(kTestPassword, GetConfigPassphrase(caps));
  EXPECT_EQ(kSecurityWpa3, GetConfigSecurity(caps));
  EXPECT_EQ(kBand5GHz, GetConfigBand(caps));
  EXPECT_EQ(kTypeCellular, GetConfigUpstream(caps));

  // Check the tethering config is reset to default properties when unloading
  // the profile.
  tethering_manager_->UnloadConfigFromProfile();
  caps = VerifyDefaultTetheringConfig(tethering_manager_);
  EXPECT_NE(kTestAPHexSSID, caps.Get<std::string>(kTetheringConfSSIDProperty));
  EXPECT_NE(kTestPassword,
            caps.Get<std::string>(kTetheringConfPassphraseProperty));
}

TEST_F(TetheringManagerTest, TetheringConfigSaveAndLoad) {
  // Load a fake tethering configuration.
  KeyValueStore config1 = GenerateFakeConfig(kTestAPHexSSID, kTestPassword);
  FromProperties(tethering_manager_, config1);

  // Save the fake tethering configuration
  FakeStore store;
  SaveConfig(tethering_manager_, &store);

  // Force the default configuration to change by unloading the profile.
  tethering_manager_->UnloadConfigFromProfile();

  // Reload the configuration
  scoped_refptr<MockProfile> profile =
      new MockProfile(&manager_, "~user/profile0");
  EXPECT_CALL(*profile, GetConstStorage()).WillRepeatedly(Return(&store));
  tethering_manager_->LoadConfigFromProfile(profile);

  // Check that the configurations are identical
  KeyValueStore config2 = GetConfig(tethering_manager_);
  EXPECT_EQ(GetConfigMAR(config1), GetConfigMAR(config2));
  EXPECT_EQ(GetConfigAutoDisable(config1), GetConfigAutoDisable(config2));
  EXPECT_EQ(GetConfigSSID(config1), GetConfigSSID(config2));
  EXPECT_EQ(GetConfigPassphrase(config1), GetConfigPassphrase(config2));
  EXPECT_EQ(GetConfigBand(config1), GetConfigBand(config2));
  EXPECT_EQ(GetConfigUpstream(config1), GetConfigUpstream(config2));
}

TEST_F(TetheringManagerTest, TetheringIsNotAllowed) {
  // Fake Tethering configuration.
  KeyValueStore config = GenerateFakeConfig(kTestAPHexSSID, kTestPassword);

  // Push a user profile
  ASSERT_TRUE(base::CreateDirectory(temp_dir_.GetPath().Append("user")));
  ASSERT_EQ(Error::kSuccess, TestCreateProfile(&manager_, kUserProfile));
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager_, kUserProfile));

  // Tethering is not allowed. SetAndPersistConfig and SetEnabled should fail
  // with error code kNotAllowed.
  SetAllowed(tethering_manager_, false);
  EXPECT_FALSE(SetAndPersistConfig(tethering_manager_, config));
  SetEnabledVerifyResult(tethering_manager_, true,
                         TetheringManager::SetEnabledResult::kNotAllowed);

  // Tethering is allowed. SetAndPersistConfig and SetEnabled should success
  SetAllowed(tethering_manager_, true);
  EXPECT_TRUE(SetAndPersistConfig(tethering_manager_, config));
  SetEnabled(tethering_manager_, true);
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringStarting);
}

TEST_F(TetheringManagerTest, TetheringInDefaultProfile) {
  SetAllowed(tethering_manager_, true);
  // SetEnabled fails for the default profile.
  ASSERT_EQ(Error::kSuccess, TestCreateProfile(&manager_, kDefaultProfile));
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager_, kDefaultProfile));
  SetEnabledVerifyResult(tethering_manager_, true,
                         TetheringManager::SetEnabledResult::kNotAllowed);
}

TEST_F(TetheringManagerTest, CheckReadinessNotAllowed) {
  base::MockOnceCallback<void(TetheringManager::EntitlementStatus)> cb;
  KeyValueStore config = GenerateFakeConfig(kTestAPHexSSID, kTestPassword);

  // Not allowed.
  tethering_manager_->CheckReadiness(cb.Get());
  EXPECT_CALL(cb, Run(TetheringManager::EntitlementStatus::kNotAllowed));
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);
}

TEST_F(TetheringManagerTest, CheckReadinessCellularUpstream) {
  base::MockOnceCallback<void(TetheringManager::EntitlementStatus)> cb;
  KeyValueStore config =
      GenerateFakeConfig("757365725F73736964", "user_password");
  SetConfigUpstream(config, TechnologyName(Technology::kCellular));
  SetAllowed(tethering_manager_, true);
  EXPECT_TRUE(FromProperties(tethering_manager_, config));

  // No cellular Device.
  tethering_manager_->CheckReadiness(cb.Get());
  EXPECT_CALL(
      cb,
      Run(TetheringManager::EntitlementStatus::kUpstreamNetworkNotAvailable));
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);

  // Set one fake ethernet Device.
  auto eth =
      new NiceMock<MockDevice>(&manager_, "eth0", "0a:0b:0c:0d:0e:0f", 1);
  ON_CALL(*eth, technology()).WillByDefault(Return(Technology::kEthernet));
  const std::vector<DeviceRefPtr> eth_devices = {eth};
  ON_CALL(manager_, FilterByTechnology(Technology::kEthernet))
      .WillByDefault(Return(eth_devices));
  auto eth_service(new MockService(&manager_));
  eth->set_selected_service_for_testing(eth_service);

  // Set one fake cellular Device.
  auto cell = MakeCellular("wwan0", "000102030405", 2);
  const std::vector<DeviceRefPtr> cell_devices = {cell};
  ON_CALL(manager_, FilterByTechnology(Technology::kCellular))
      .WillByDefault(Return(cell_devices));
  scoped_refptr<MockCellularService> cell_service =
      new MockCellularService(&manager_, cell);
  AddServiceToCellularProvider(cell_service);
  cell->set_selected_service_for_testing(cell_service);

  // Both Ethernet Service and Cellular Service are disconnected.
  EXPECT_CALL(*eth_service, IsConnected(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(*cell_service, state())
      .WillRepeatedly(Return(Service::kStateIdle));
  tethering_manager_->CheckReadiness(cb.Get());
  EXPECT_CALL(
      cb,
      Run(TetheringManager::EntitlementStatus::kUpstreamNetworkNotAvailable));
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);

  // Ethernet Service is connected, Cellular Service is disconnected.
  EXPECT_CALL(*eth_service, IsConnected(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*cell_service, state())
      .WillRepeatedly(Return(Service::kStateIdle));
  tethering_manager_->CheckReadiness(cb.Get());
  EXPECT_CALL(
      cb,
      Run(TetheringManager::EntitlementStatus::kUpstreamNetworkNotAvailable));
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);

  // Ethernet Service is disconnected, Cellular Service is connected.
  EXPECT_CALL(*eth_service, IsConnected(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(*cell_service, state())
      .WillRepeatedly(Return(Service::kStateConnected));
  EXPECT_CALL(*cellular_service_provider_, TetheringEntitlementCheck(_));
  tethering_manager_->CheckReadiness(cb.Get());
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);
  Mock::VerifyAndClearExpectations(cellular_service_provider_);

  // Both Ethernet Service and Cellular Service are connected.
  EXPECT_CALL(*eth_service, IsConnected(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*cell_service, state())
      .WillRepeatedly(Return(Service::kStateConnected));
  EXPECT_CALL(*cellular_service_provider_, TetheringEntitlementCheck(_));
  tethering_manager_->CheckReadiness(cb.Get());
  DispatchPendingEvents();
}

TEST_F(TetheringManagerTest, CheckReadinessEthernetUpstream) {
  base::MockOnceCallback<void(TetheringManager::EntitlementStatus)> cb;
  KeyValueStore config =
      GenerateFakeConfig("757365725F73736964", "user_password");
  SetConfigUpstream(config, TechnologyName(Technology::kEthernet));
  SetAllowed(tethering_manager_, true);
  EXPECT_TRUE(FromProperties(tethering_manager_, config));

  // No ethernet Device.
  tethering_manager_->CheckReadiness(cb.Get());
  EXPECT_CALL(
      cb,
      Run(TetheringManager::EntitlementStatus::kUpstreamNetworkNotAvailable));
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);

  // Set one fake ethernet Device.
  auto eth =
      new NiceMock<MockDevice>(&manager_, "eth0", "0a:0b:0c:0d:0e:0f", 1);
  ON_CALL(*eth, technology()).WillByDefault(Return(Technology::kEthernet));
  const std::vector<DeviceRefPtr> eth_devices = {eth};
  ON_CALL(manager_, FilterByTechnology(Technology::kEthernet))
      .WillByDefault(Return(eth_devices));
  auto eth_service(new MockService(&manager_));
  eth->set_selected_service_for_testing(eth_service);

  // Set one fake cellular Device.
  auto cell = MakeCellular("wwan0", "000102030405", 2);
  const std::vector<DeviceRefPtr> cell_devices = {cell};
  ON_CALL(manager_, FilterByTechnology(Technology::kCellular))
      .WillByDefault(Return(cell_devices));
  scoped_refptr<MockCellularService> cell_service =
      new MockCellularService(&manager_, cell);
  AddServiceToCellularProvider(cell_service);
  cell->set_selected_service_for_testing(cell_service);

  EXPECT_CALL(*cellular_service_provider_, TetheringEntitlementCheck(_))
      .Times(0);

  // Both Ethernet Service and Cellular Service are disconnected.
  EXPECT_CALL(*eth_service, IsConnected(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(*cell_service, state())
      .WillRepeatedly(Return(Service::kStateIdle));
  tethering_manager_->CheckReadiness(cb.Get());
  EXPECT_CALL(
      cb,
      Run(TetheringManager::EntitlementStatus::kUpstreamNetworkNotAvailable));
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);

  // Ethernet Service is connected, Cellular Service is disconnected.
  EXPECT_CALL(*eth_service, IsConnected(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*cell_service, state())
      .WillRepeatedly(Return(Service::kStateIdle));
  tethering_manager_->CheckReadiness(cb.Get());
  EXPECT_CALL(cb, Run(TetheringManager::EntitlementStatus::kReady));
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);

  // Ethernet Service is disconnected, Cellular Service is connected.
  EXPECT_CALL(*eth_service, IsConnected(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(*cell_service, state())
      .WillRepeatedly(Return(Service::kStateConnected));
  tethering_manager_->CheckReadiness(cb.Get());
  EXPECT_CALL(
      cb,
      Run(TetheringManager::EntitlementStatus::kUpstreamNetworkNotAvailable));
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);

  // Both Ethernet Service and Cellular Service are connected.
  EXPECT_CALL(*eth_service, IsConnected(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*cell_service, state())
      .WillRepeatedly(Return(Service::kStateConnected));
  tethering_manager_->CheckReadiness(cb.Get());
  EXPECT_CALL(cb, Run(TetheringManager::EntitlementStatus::kReady));
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);
}

TEST_F(TetheringManagerTest, SetEnabledResultName) {
  EXPECT_EQ("success", TetheringManager::SetEnabledResultName(
                           TetheringManager::SetEnabledResult::kSuccess));
  EXPECT_EQ("failure", TetheringManager::SetEnabledResultName(
                           TetheringManager::SetEnabledResult::kFailure));
  EXPECT_EQ("not_allowed",
            TetheringManager::SetEnabledResultName(
                TetheringManager::SetEnabledResult::kNotAllowed));
  EXPECT_EQ("invalid_properties",
            TetheringManager::SetEnabledResultName(
                TetheringManager::SetEnabledResult::kInvalidProperties));
  EXPECT_EQ(
      "upstream_not_available",
      TetheringManager::SetEnabledResultName(
          TetheringManager::SetEnabledResult::kUpstreamNetworkNotAvailable));
}

TEST_F(TetheringManagerTest, StartTetheringSessionSuccessWithCellularUpstream) {
  TetheringPrerequisite(tethering_manager_);

  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  SetEnabled(tethering_manager_, true);
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringStarting);
  EXPECT_CALL(*patchpanel_, CreateTetheredNetwork("ap0", "wwan0", _, _, _))
      .WillOnce(Return(true));

  // Downstream device event service up.
  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  DownStreamDeviceEvent(tethering_manager_,
                        LocalDevice::DeviceEvent::kServiceUp,
                        hotspot_device_.get());

  // Upstream network fetched.
  OnUpstreamNetworkAcquired(tethering_manager_,
                            TetheringManager::SetEnabledResult::kSuccess);

  // Tethering network created.
  OnDownstreamNetworkReady(tethering_manager_, MakeFd());

  VerifyResult(TetheringManager::SetEnabledResult::kSuccess);
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringActive);
  Mock::VerifyAndClearExpectations(&manager_);
}

TEST_F(TetheringManagerTest, StartTetheringSessionSuccessWithEthernetUpstream) {
  MockNetwork eth_network(kTestInterfaceIndex + 1, "eth0",
                          Technology::kEthernet);
  ON_CALL(eth_network, HasInternetConnectivity()).WillByDefault(Return(true));
  ON_CALL(eth_network, IsConnected()).WillByDefault(Return(true));
  scoped_refptr<MockService> eth_service = new MockService(&manager_);
  EXPECT_CALL(manager_, GetFirstEthernetService())
      .WillOnce(Return(eth_service));
  EXPECT_CALL(manager_, FindActiveNetworkFromService(_))
      .WillOnce(Return(&eth_network));

  EXPECT_CALL(*patchpanel_, CreateTetheredNetwork("ap0", "eth0", _, _, _))
      .WillOnce(Return(true));

  // TetheringManager will evaluate the downstream service readiness as soon as
  // it finds the ethernet upstream network.
  ON_CALL(*hotspot_device_.get(), IsServiceUp()).WillByDefault(Return(false));

  // Change the upstream technology to ethernet.
  TetheringPrerequisite(tethering_manager_);
  KeyValueStore config =
      GenerateFakeConfig("757365725F73736964", "user_password");
  SetConfigUpstream(config, TechnologyName(Technology::kEthernet));
  EXPECT_TRUE(FromProperties(tethering_manager_, config));

  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  SetEnabled(tethering_manager_, true);
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringStarting);
  Mock::VerifyAndClearExpectations(&manager_);

  // Downstream device event service up.
  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  ON_CALL(*hotspot_device_.get(), IsServiceUp()).WillByDefault(Return(true));
  DownStreamDeviceEvent(tethering_manager_,
                        LocalDevice::DeviceEvent::kServiceUp,
                        hotspot_device_.get());

  // Tethering network created.
  OnDownstreamNetworkReady(tethering_manager_, MakeFd());

  Mock::VerifyAndClearExpectations(&manager_);
  VerifyResult(TetheringManager::SetEnabledResult::kSuccess);
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringActive);
}

TEST_F(TetheringManagerTest,
       StartTetheringSessionTetheredNetworkImmediateFailure) {
  TetheringPrerequisite(tethering_manager_);

  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  SetEnabled(tethering_manager_, true);
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringStarting);
  // Tethering network creation request fails.
  EXPECT_CALL(*patchpanel_, CreateTetheredNetwork("ap0", "wwan0", _, _, _))
      .WillOnce(Return(false));

  // Downstream device event service up.
  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  DownStreamDeviceEvent(tethering_manager_,
                        LocalDevice::DeviceEvent::kServiceUp,
                        hotspot_device_.get());

  // Upstream network fetched.
  OnUpstreamNetworkAcquired(tethering_manager_,
                            TetheringManager::SetEnabledResult::kSuccess);

  VerifyResult(TetheringManager::SetEnabledResult::kFailure);
  CheckTetheringStopping(tethering_manager_, kTetheringIdleReasonError);
}

TEST_F(TetheringManagerTest,
       StartTetheringSessionTetheredNetworkDelayedFailure) {
  TetheringPrerequisite(tethering_manager_);

  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  SetEnabled(tethering_manager_, true);
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringStarting);
  EXPECT_CALL(*patchpanel_, CreateTetheredNetwork("ap0", "wwan0", _, _, _))
      .WillOnce(Return(true));

  // Downstream device event service up.
  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  DownStreamDeviceEvent(tethering_manager_,
                        LocalDevice::DeviceEvent::kServiceUp,
                        hotspot_device_.get());

  // Upstream network fetched.
  OnUpstreamNetworkAcquired(tethering_manager_,
                            TetheringManager::SetEnabledResult::kSuccess);

  // Tethering network creation request fails
  OnDownstreamNetworkReady(tethering_manager_, base::ScopedFD(-1));

  VerifyResult(TetheringManager::SetEnabledResult::kFailure);
  CheckTetheringStopping(tethering_manager_, kTetheringIdleReasonError);
}

TEST_F(TetheringManagerTest,
       StartTetheringSessionTetheredNetworkAlreadyStarted) {
  TetheringPrerequisite(tethering_manager_);

  // Tethering session is started.
  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  SetEnabled(tethering_manager_, true);
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringStarting);
  Mock::VerifyAndClearExpectations(&manager_);

  // Downstream device event service up.
  DownStreamDeviceEvent(tethering_manager_,
                        LocalDevice::DeviceEvent::kServiceUp,
                        hotspot_device_.get());

  // Upstream network fetched.
  EXPECT_CALL(*patchpanel_, CreateTetheredNetwork("ap0", "wwan0", _, _, _))
      .Times(1)
      .WillOnce(Return(true));
  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(0);
  OnUpstreamNetworkAcquired(tethering_manager_,
                            TetheringManager::SetEnabledResult::kSuccess);
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringStarting);
  Mock::VerifyAndClearExpectations(&manager_);

  // Force another LocalDevice::DeviceEvent::kServiceUp event for the
  // downstream network.
  DownStreamDeviceEvent(tethering_manager_,
                        LocalDevice::DeviceEvent::kServiceUp,
                        hotspot_device_.get());

  VerifyResult(TetheringManager::SetEnabledResult::kFailure);
  CheckTetheringStopping(tethering_manager_, kTetheringIdleReasonError);
}

TEST_F(TetheringManagerTest, StartTetheringSessionUpstreamNetworkNotConnected) {
  TetheringPrerequisite(tethering_manager_);

  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  SetEnabled(tethering_manager_, true);
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringStarting);
  Mock::VerifyAndClearExpectations(&manager_);

  // Upstream Network fetched but the the Network has disconnected.
  EXPECT_CALL(*network_, IsConnected()).WillRepeatedly(Return(false));
  OnUpstreamNetworkAcquired(tethering_manager_,
                            TetheringManager::SetEnabledResult::kSuccess);

  VerifyResult(TetheringManager::SetEnabledResult::kFailure);
  // Expect idle state: there is no downstream device to tear down.
  CheckTetheringIdle(tethering_manager_, kTetheringIdleReasonError);
}

TEST_F(TetheringManagerTest, StartTetheringSessionUpstreamNetworkNotReady) {
  TetheringPrerequisite(tethering_manager_);

  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  SetEnabled(tethering_manager_, true);
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringStarting);
  EXPECT_CALL(*patchpanel_, CreateTetheredNetwork("ap0", "wwan0", _, _, _))
      .WillOnce(Return(true));

  // Downstream device event service up.
  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  DownStreamDeviceEvent(tethering_manager_,
                        LocalDevice::DeviceEvent::kServiceUp,
                        hotspot_device_.get());

  // Upstream network fetched. Network not ready upon fetch and will be ready
  // later.
  EXPECT_CALL(*network_, HasInternetConnectivity())
      .WillOnce(Return(false))
      .WillRepeatedly(DoDefault());
  OnUpstreamNetworkAcquired(tethering_manager_,
                            TetheringManager::SetEnabledResult::kSuccess);
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringStarting);

  // Tethering network created.
  OnDownstreamNetworkReady(tethering_manager_, MakeFd());

  // Feed network validation result event.
  OnUpstreamNetworkValidationResult(tethering_manager_);
  VerifyResult(TetheringManager::SetEnabledResult::kSuccess);
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringActive);
  Mock::VerifyAndClearExpectations(&manager_);
}

TEST_F(TetheringManagerTest, FailToCreateLocalInterface) {
  TetheringPrerequisite(tethering_manager_);
  EXPECT_CALL(*wifi_provider_, CreateHotspotDevice(_, _, _, _))
      .WillOnce(Return(nullptr));
  EXPECT_CALL(*hotspot_device_.get(), ConfigureService(_)).Times(0);
  SetEnabledVerifyResult(
      tethering_manager_, true,
      TetheringManager::SetEnabledResult::kDownstreamWiFiFailure);
  CheckTetheringIdle(tethering_manager_, kTetheringIdleReasonError);
}

TEST_F(TetheringManagerTest, FailToConfigureService) {
  TetheringPrerequisite(tethering_manager_);
  EXPECT_CALL(*wifi_provider_, CreateHotspotDevice(_, _, _, _))
      .WillOnce(Return(hotspot_device_));
  EXPECT_CALL(*hotspot_device_.get(), ConfigureService(_))
      .WillOnce(Return(false));
  EXPECT_CALL(*hotspot_device_.get(), DeconfigureService())
      .WillOnce(Return(true));

  SetEnabledVerifyResult(
      tethering_manager_, true,
      TetheringManager::SetEnabledResult::kDownstreamWiFiFailure);
  CheckTetheringIdle(tethering_manager_, kTetheringIdleReasonError);
}

TEST_F(TetheringManagerTest, FailToFetchUpstreamNetwork) {
  TetheringPrerequisite(tethering_manager_);
  SetEnabled(tethering_manager_, true);
  // Upstream network fetch failed.
  OnUpstreamNetworkAcquired(
      tethering_manager_,
      TetheringManager::SetEnabledResult::kUpstreamNetworkNotAvailable);
  VerifyResult(
      TetheringManager::SetEnabledResult::kUpstreamNetworkNotAvailable);
  CheckTetheringIdle(tethering_manager_, kTetheringIdleReasonError);
}

TEST_F(TetheringManagerTest, UserStopTetheringSession) {
  TetheringPrerequisite(tethering_manager_);
  SetEnabledVerifyResult(tethering_manager_, true,
                         TetheringManager::SetEnabledResult::kSuccess);

  SetEnabledVerifyResult(tethering_manager_, false,
                         TetheringManager::SetEnabledResult::kSuccess);
  CheckTetheringIdle(tethering_manager_, kTetheringIdleReasonClientStop);
}

TEST_F(TetheringManagerTest, TetheringStopWhenUserLogout) {
  TetheringPrerequisite(tethering_manager_);
  SetEnabledVerifyResult(tethering_manager_, true,
                         TetheringManager::SetEnabledResult::kSuccess);

  // Log out user should also stop active tethering session and put tethering
  // state to idle.
  EXPECT_EQ(Error::kSuccess, TestPopProfile(&manager_, kUserProfile));
  CheckTetheringStopping(tethering_manager_, kTetheringIdleReasonUserExit);
}

TEST_F(TetheringManagerTest, DeviceEventInterfaceDisabled) {
  TetheringPrerequisite(tethering_manager_);
  SetEnabledVerifyResult(tethering_manager_, true,
                         TetheringManager::SetEnabledResult::kSuccess);

  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  DownStreamDeviceEvent(tethering_manager_,
                        LocalDevice::DeviceEvent::kInterfaceDisabled,
                        hotspot_device_.get());
  DispatchPendingEvents();
  CheckTetheringStopping(tethering_manager_, kTetheringIdleReasonError);
}

TEST_F(TetheringManagerTest, DeviceEventServiceDown) {
  TetheringPrerequisite(tethering_manager_);
  SetEnabledVerifyResult(tethering_manager_, true,
                         TetheringManager::SetEnabledResult::kSuccess);

  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  DownStreamDeviceEvent(tethering_manager_,
                        LocalDevice::DeviceEvent::kServiceDown,
                        hotspot_device_.get());
  DispatchPendingEvents();
  CheckTetheringStopping(tethering_manager_, kTetheringIdleReasonError);
}

TEST_F(TetheringManagerTest, UpstreamNetworkStopped) {
  TetheringPrerequisite(tethering_manager_);
  SetEnabledVerifyResult(tethering_manager_, true,
                         TetheringManager::SetEnabledResult::kSuccess);

  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  OnUpstreamNetworkStopped(tethering_manager_);
  CheckTetheringStopping(tethering_manager_,
                         kTetheringIdleReasonUpstreamDisconnect);
}

TEST_F(TetheringManagerTest, UpstreamNetworkDestroyed) {
  TetheringPrerequisite(tethering_manager_);
  SetEnabledVerifyResult(tethering_manager_, true,
                         TetheringManager::SetEnabledResult::kSuccess);

  // State change from active to stopping then to idle
  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(2);
  OnUpstreamNetworkDestroyed(tethering_manager_);
  CheckTetheringIdle(tethering_manager_,
                     kTetheringIdleReasonUpstreamDisconnect);
}

TEST_F(TetheringManagerTest, InterfaceDisabledWhenTetheringIsStarting) {
  TetheringPrerequisite(tethering_manager_);

  SetEnabled(tethering_manager_, true);
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringStarting);

  DownStreamDeviceEvent(tethering_manager_,
                        LocalDevice::DeviceEvent::kInterfaceDisabled,
                        hotspot_device_.get());
  VerifyResult(TetheringManager::SetEnabledResult::kDownstreamWiFiFailure);
  CheckTetheringIdle(tethering_manager_, kTetheringIdleReasonError);
}

TEST_F(TetheringManagerTest, UpstreamNetworkValidationFailed) {
  TetheringPrerequisite(tethering_manager_);

  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  SetEnabled(tethering_manager_, true);
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringStarting);

  // Downstream device event service up.
  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  DownStreamDeviceEvent(tethering_manager_,
                        LocalDevice::DeviceEvent::kServiceUp,
                        hotspot_device_.get());

  // Upstream network fetched. Network not ready.
  EXPECT_CALL(*network_, HasInternetConnectivity())
      .WillRepeatedly(Return(false));
  ON_CALL(*patchpanel_, CreateTetheredNetwork("ap0", "wwan0", _, _, _))
      .WillByDefault(Return(true));
  OnUpstreamNetworkAcquired(tethering_manager_,
                            TetheringManager::SetEnabledResult::kSuccess);
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringStarting);

  // Downstream network is fully configured. Upstream network is not yet ready.
  OnDownstreamNetworkReady(tethering_manager_, MakeFd());
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringStarting);

  // Feed network validation result event.
  OnUpstreamNetworkValidationResult(tethering_manager_);
  VerifyResult(
      TetheringManager::SetEnabledResult::kUpstreamNetworkNotAvailable);
  CheckTetheringStopping(tethering_manager_,
                         kTetheringIdleReasonUpstreamDisconnect);
}

TEST_F(TetheringManagerTest, DeviceEventPeerConnectedDisconnected) {
  TetheringPrerequisite(tethering_manager_);
  SetEnabledVerifyResult(tethering_manager_, true,
                         TetheringManager::SetEnabledResult::kSuccess);

  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  DownStreamDeviceEvent(tethering_manager_,
                        LocalDevice::DeviceEvent::kPeerConnected,
                        hotspot_device_.get());

  EXPECT_CALL(manager_, TetheringStatusChanged()).Times(1);
  DownStreamDeviceEvent(tethering_manager_,
                        LocalDevice::DeviceEvent::kPeerDisconnected,
                        hotspot_device_.get());
  Mock::VerifyAndClearExpectations(&manager_);
}

TEST_F(TetheringManagerTest, GetStatus) {
  // Check tethering status when idle.
  auto status = GetStatus(tethering_manager_);
  EXPECT_EQ(status.Get<std::string>(kTetheringStatusStateProperty),
            kTetheringStateIdle);
  EXPECT_EQ(status.Get<std::string>(kTetheringStatusIdleReasonProperty),
            kTetheringIdleReasonInitialState);
  EXPECT_FALSE(
      status.Contains<std::string>(kTetheringStatusUpstreamTechProperty));
  EXPECT_FALSE(
      status.Contains<std::string>(kTetheringStatusDownstreamTechProperty));
  EXPECT_FALSE(status.Contains<Stringmaps>(kTetheringStatusClientsProperty));

  // Enabled tethering.
  TetheringPrerequisite(tethering_manager_);
  SetEnabledVerifyResult(tethering_manager_, true,
                         TetheringManager::SetEnabledResult::kSuccess);
  status = GetStatus(tethering_manager_);
  EXPECT_EQ(status.Get<std::string>(kTetheringStatusStateProperty),
            kTetheringStateActive);
  EXPECT_EQ(status.Get<std::string>(kTetheringStatusUpstreamTechProperty),
            kTypeCellular);
  EXPECT_EQ(status.Get<std::string>(kTetheringStatusDownstreamTechProperty),
            kTypeWifi);
  EXPECT_EQ(status.Get<Stringmaps>(kTetheringStatusClientsProperty).size(), 0);
  EXPECT_FALSE(
      status.Contains<std::string>(kTetheringStatusIdleReasonProperty));

  // Connect 2 clients.
  std::vector<std::vector<uint8_t>> clients;
  clients.push_back({00, 11, 22, 33, 44, 55});
  clients.push_back({00, 11, 22, 33, 44, 66});
  EXPECT_CALL(*hotspot_device_.get(), GetStations()).WillOnce(Return(clients));
  status = GetStatus(tethering_manager_);
  EXPECT_EQ(status.Get<Stringmaps>(kTetheringStatusClientsProperty).size(), 2);

  // Stop tethering.
  ON_CALL(*hotspot_device_.get(), DeconfigureService())
      .WillByDefault(Return(true));
  SetEnabledVerifyResult(tethering_manager_, false,
                         TetheringManager::SetEnabledResult::kSuccess);
  status = GetStatus(tethering_manager_);
  EXPECT_EQ(status.Get<std::string>(kTetheringStatusStateProperty),
            kTetheringStateIdle);
  EXPECT_EQ(status.Get<std::string>(kTetheringStatusIdleReasonProperty),
            kTetheringIdleReasonClientStop);
  EXPECT_FALSE(
      status.Contains<std::string>(kTetheringStatusUpstreamTechProperty));
  EXPECT_FALSE(
      status.Contains<std::string>(kTetheringStatusDownstreamTechProperty));
  EXPECT_FALSE(status.Contains<Stringmaps>(kTetheringStatusClientsProperty));
}

TEST_F(TetheringManagerTest, InactiveTimer) {
  // Start tethering.
  TetheringPrerequisite(tethering_manager_);
  // Inactive timer is not triggered when tethering is not active.
  EXPECT_TRUE(GetInactiveTimer(tethering_manager_).IsCancelled());
  SetEnabledVerifyResult(tethering_manager_, true,
                         TetheringManager::SetEnabledResult::kSuccess);
  // Inactive timer should be armed when tethering is active and no client is
  // connected.
  EXPECT_FALSE(GetInactiveTimer(tethering_manager_).IsCancelled());

  // Connect client to the hotspot.
  std::vector<std::vector<uint8_t>> clients;
  clients.push_back({00, 11, 22, 33, 44, 55});
  EXPECT_CALL(*hotspot_device_.get(), GetStations()).WillOnce(Return(clients));
  DownStreamDeviceEvent(tethering_manager_,
                        LocalDevice::DeviceEvent::kPeerConnected,
                        hotspot_device_.get());
  DispatchPendingEvents();
  // Inactive timer should be canceled if at least one client is connected.
  EXPECT_TRUE(GetInactiveTimer(tethering_manager_).IsCancelled());

  clients.clear();
  EXPECT_CALL(*hotspot_device_.get(), GetStations()).WillOnce(Return(clients));
  DownStreamDeviceEvent(tethering_manager_,
                        LocalDevice::DeviceEvent::kPeerDisconnected,
                        hotspot_device_.get());
  DispatchPendingEvents();
  // Inactive timer should be re-armed when tethering is active and the last
  // client is gone.
  EXPECT_FALSE(GetInactiveTimer(tethering_manager_).IsCancelled());
}

TEST_F(TetheringManagerTest, TetheringStartTimer) {
  // Start tethering.
  TetheringPrerequisite(tethering_manager_);
  EXPECT_TRUE(GetStartTimer(tethering_manager_).IsCancelled());
  SetEnabled(tethering_manager_, true);
  EXPECT_FALSE(GetStartTimer(tethering_manager_).IsCancelled());
  EXPECT_EQ(TetheringState(tethering_manager_),
            TetheringManager::TetheringState::kTetheringStarting);

  // Tethering start timeout
  OnStartingTetheringTimeout(tethering_manager_);
  CheckTetheringIdle(tethering_manager_, kTetheringIdleReasonError);
}

TEST_F(TetheringManagerTest, TetheringStopTimer) {
  TetheringPrerequisite(tethering_manager_);
  SetEnabledVerifyResult(tethering_manager_, true,
                         TetheringManager::SetEnabledResult::kSuccess);
  // Stop tethering.
  EXPECT_TRUE(GetStopTimer(tethering_manager_).IsCancelled());
  SetEnabled(tethering_manager_, false);
  EXPECT_FALSE(GetStopTimer(tethering_manager_).IsCancelled());
  // Tethering stop timeout
  OnStoppingTetheringTimeout(tethering_manager_);
  VerifyResult(TetheringManager::SetEnabledResult::kUpstreamFailure);
  CheckTetheringIdle(tethering_manager_, kTetheringIdleReasonClientStop);
}

TEST_F(TetheringManagerTest, MARWithSSIDChange) {
  TetheringPrerequisite(tethering_manager_);

  // Upon initialization TetheringManager generates some config.  Let's take
  // a snapshot of the SSID/MAC (to test if MAC changes upon SSID change).
  std::string ini_ssid = tethering_manager_->hex_ssid_;
  std::string ini_mac = tethering_manager_->stable_mac_addr_.ToString();

  // Change SSID to cause regeneration of MAC address.
  KeyValueStore args = GenerateFakeConfig(kTestAPHexSSID, kTestPassword);
  // Turn off randomization.
  SetConfigMAR(args, false);
  EXPECT_TRUE(SetAndPersistConfig(tethering_manager_, args));
  std::string mac = tethering_manager_->stable_mac_addr_.ToString();
  ASSERT_NE(ini_ssid, kTestAPHexSSID);
  EXPECT_NE(ini_mac, mac);

  // Test 1st argument for CreateHotspotDevice (MAC as a hex-string).
  EXPECT_CALL(*wifi_provider_, CreateHotspotDevice(Eq(mac), _, _, _))
      .WillOnce(Return(hotspot_device_));
  SetEnabled(tethering_manager_, true);
}

MATCHER_P(IsContained, container, "") {
  return base::Contains(container, arg);
}

TEST_F(TetheringManagerTest, MARWithTetheringRestart) {
  TetheringPrerequisite(tethering_manager_);
  std::set<std::string> known_macs;
  known_macs.insert(tethering_manager_->stable_mac_addr_.ToString());

  auto tether_onoff = [&]() {
    EXPECT_CALL(*wifi_provider_,
                CreateHotspotDevice(Not(IsContained(known_macs)), _, _, _))
        .WillOnce(
            DoAll(WithArg<0>(Invoke([&](auto mac) { known_macs.insert(mac); })),
                  Return(hotspot_device_)));
    SetEnabledVerifyResult(tethering_manager_, true,
                           TetheringManager::SetEnabledResult::kSuccess);
    EXPECT_EQ(TetheringState(tethering_manager_),
              TetheringManager::TetheringState::kTetheringActive);
    SetEnabledVerifyResult(tethering_manager_, false,
                           TetheringManager::SetEnabledResult::kSuccess);
    CheckTetheringIdle(tethering_manager_, kTetheringIdleReasonClientStop);
  };

  for (int i = 0; i < 4; ++i) {
    tether_onoff();
  }
}

TEST_F(TetheringManagerTest, CheckMACStored) {
  TetheringPrerequisite(tethering_manager_);

  // Change SSID to cause regeneration of MAC address.
  KeyValueStore args;
  SetConfigSSID(args, kTestAPHexSSID);
  // Turn off randomization to check the MAC is being used at the end.
  SetConfigMAR(args, false);
  EXPECT_TRUE(SetAndPersistConfig(tethering_manager_, args));

  std::string ini_mac = tethering_manager_->stable_mac_addr_.ToString();

  // Now PopProfile and check that MAC is different.
  EXPECT_EQ(Error::kSuccess, TestPopProfile(&manager_, kUserProfile));
  EXPECT_NE(ini_mac, tethering_manager_->stable_mac_addr_.ToString());

  // Repush the profile and check that MAC returns to its original value.
  EXPECT_EQ(Error::kSuccess, TestPushProfile(&manager_, kUserProfile));
  EXPECT_EQ(ini_mac, tethering_manager_->stable_mac_addr_.ToString());

  // And test that it is actually used.
  EXPECT_CALL(*wifi_provider_, CreateHotspotDevice(Eq(ini_mac), _, _, _))
      .WillOnce(Return(hotspot_device_));
  SetEnabled(tethering_manager_, true);
}

TEST_F(TetheringManagerTest, SelectFrequency_Empty) {
  WiFiPhy::Frequencies frequencies;

  int freq;
  tethering_manager_->band_ = WiFiBand::kLowBand;
  freq = tethering_manager_->SelectFrequency(frequencies);
  EXPECT_EQ(freq, -1);
  tethering_manager_->band_ = WiFiBand::kHighBand;
  freq = tethering_manager_->SelectFrequency(frequencies);
  EXPECT_EQ(freq, -1);
  tethering_manager_->band_ = WiFiBand::kAllBands;
  freq = tethering_manager_->SelectFrequency(frequencies);
  EXPECT_EQ(freq, -1);
}

TEST_F(TetheringManagerTest, SelectFrequency_NoValidHB) {
  WiFiPhy::Frequencies frequencies = {
      {0,
       {
           {.value = 2412},  // Channel 1
           {.value = 2417},  // Channel 2
           {.value = 2422},  // Channel 3
           {.value = 2467},  // Channel 12
           {.value = 2472},  // Channel 13
       }},
      {1,
       {
           {.flags = 1 << NL80211_FREQUENCY_ATTR_NO_IR, .value = 5200},
           {.flags = 1 << NL80211_FREQUENCY_ATTR_RADAR, .value = 5300},
       }}};
  int freq;
  tethering_manager_->band_ = WiFiBand::kAllBands;
  freq = tethering_manager_->SelectFrequency(frequencies);
  EXPECT_GE(freq, kLBStartFreq);
  EXPECT_LE(freq, kChan11Freq);  // Should avoid channel greater than channel 11
  EXPECT_TRUE(base::Contains(frequencies[0], uint32_t(freq),
                             [](auto& f) { return f.value; }));
}

TEST_F(TetheringManagerTest, SelectFrequency_DualBandsAvailable) {
  WiFiPhy::Frequencies frequencies = {
      {0,
       {
           {.value = 2412},  // Channel 1
           {.value = 2417},  // Channel 2
           {.value = 2422},  // Channel 3
           {.value = 2467},  // Channel 12
           {.value = 2472},  // Channel 13
       }},
      {1,
       {
           {.value = 5180},  // Channel 36
           {.value = 5200},  // Channel 40
           {.value = 5220},  // Channel 44
           {.value = 5240},  // Channel 48
           {.flags = 1 << NL80211_FREQUENCY_ATTR_RADAR,
            .value = 5260},  // Channel 52
           {.flags = 1 << NL80211_FREQUENCY_ATTR_RADAR,
            .value = 5280},  // Channel 56
           {.flags = 1 << NL80211_FREQUENCY_ATTR_NO_IR,
            .value = 5300},  // Channel 60
           {.flags = 1 << NL80211_FREQUENCY_ATTR_NO_IR,
            .value = 5320},  // Channel 64
           {.flags = 1 << NL80211_FREQUENCY_ATTR_DISABLED,
            .value = 5340},  // Channel 68
           {.flags = 1 << NL80211_FREQUENCY_ATTR_DISABLED,
            .value = 5360},  // Channel 72
       }}};

  int freq;
  tethering_manager_->band_ = WiFiBand::kLowBand;
  freq = tethering_manager_->SelectFrequency(frequencies);
  EXPECT_GE(freq, kLBStartFreq);
  EXPECT_LE(freq, kChan11Freq);  // Should avoid channel greater than channel 11
  EXPECT_TRUE(
      base::Contains(frequencies[WiFiBandToNl(tethering_manager_->band_)],
                     uint32_t(freq), [](auto& f) { return f.value; }));

  tethering_manager_->band_ = WiFiBand::kHighBand;
  freq = tethering_manager_->SelectFrequency(frequencies);
  EXPECT_GE(freq, kHBStartFreq);
  EXPECT_LE(freq, kHBEndFreq);
  EXPECT_TRUE(
      base::Contains(frequencies[WiFiBandToNl(tethering_manager_->band_)],
                     uint32_t(freq), [](auto& f) { return f.value; }));

  // For other preferences the selected frequency should be in 2.4 or 5GHz,
  // however with a valid 5GHz frequency it should be preferred.
  tethering_manager_->band_ = WiFiBand::kAllBands;
  freq = tethering_manager_->SelectFrequency(frequencies);
  EXPECT_GE(freq, kHBStartFreq);
  EXPECT_LE(freq, kHBEndFreq);
  EXPECT_TRUE(base::Contains(frequencies[WiFiBandToNl(WiFiBand::kHighBand)],
                             uint32_t(freq), [](auto& f) { return f.value; }));
}

}  // namespace shill
