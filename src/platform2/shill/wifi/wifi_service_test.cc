// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi_service.h"

#include <limits>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/test/simple_test_clock.h>
#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/event_dispatcher.h"
#include "shill/manager.h"
#include "shill/metrics.h"
#include "shill/mock_adaptors.h"
#include "shill/mock_certificate_file.h"
#include "shill/mock_control.h"
#include "shill/mock_eap_credentials.h"
#include "shill/mock_log.h"
#include "shill/mock_manager.h"
#include "shill/mock_profile.h"
#include "shill/mock_service.h"
#include "shill/net/ieee80211.h"
#include "shill/net/mock_netlink_manager.h"
#include "shill/network/mock_network.h"
#include "shill/refptr_types.h"
#include "shill/service_property_change_test.h"
#include "shill/store/fake_store.h"
#include "shill/store/property_store_test.h"
#include "shill/supplicant/wpa_supplicant.h"
#include "shill/technology.h"
#include "shill/tethering.h"
#include "shill/wifi/mock_wake_on_wifi.h"
#include "shill/wifi/mock_wifi.h"
#include "shill/wifi/mock_wifi_provider.h"
#include "shill/wifi/wifi_endpoint.h"

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::DoAll;
using ::testing::EndsWith;
using ::testing::HasSubstr;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::SetArgPointee;
using ::testing::StrEq;
using ::testing::StrictMock;
using ::testing::StrNe;

namespace shill {

class WiFiServiceTest : public PropertyStoreTest {
 public:
  WiFiServiceTest()
      : mock_manager_(control_interface(), dispatcher(), metrics()),
        wifi_(new NiceMock<MockWiFi>(
            manager(), "wifi", fake_mac, 0, 0, new MockWakeOnWiFi())),
        provider_(&mock_manager_),
        simple_ssid_(1, 'a'),
        simple_ssid_string_("a") {}
  ~WiFiServiceTest() override = default;

 protected:
  static const char fake_mac[];

  MockEapCredentials* SetMockEap(const WiFiServiceRefPtr& service) {
    MockEapCredentials* eap = new MockEapCredentials();
    service->eap_.reset(eap);  // Passes ownership.
    return eap;
  }
  bool SetPassphrase(WiFiServiceRefPtr service, const std::string& passphrase) {
    Error error;
    service->SetPassphrase(passphrase, &error);
    return error.IsSuccess();
  }
  bool CheckConnectable(const std::string& security_class,
                        const char* passphrase,
                        bool is_1x_connectable) {
    WiFiServiceRefPtr service = MakeSimpleService(security_class);
    if (passphrase)
      SetPassphrase(service, passphrase);
    MockEapCredentials* eap = SetMockEap(service);
    EXPECT_CALL(*eap, IsConnectable())
        .WillRepeatedly(Return(is_1x_connectable));
    const std::string kKeyManagement8021x(
        WPASupplicant::kKeyManagementIeee8021X);
    if (security_class == kSecurityClassWep && is_1x_connectable) {
      EXPECT_CALL(*eap, key_management())
          .WillRepeatedly(ReturnRef(kKeyManagement8021x));
    }
    service->OnEapCredentialsChanged(Service::kReasonCredentialsLoaded);
    return service->connectable();
  }
  WiFiEndpointRefPtr MakeEndpoint(
      const std::string& ssid,
      const std::string& bssid,
      uint16_t frequency,
      int16_t signal_dbm,
      const WiFiEndpoint::SecurityFlags& security_flags) {
    return WiFiEndpoint::MakeEndpoint(nullptr, wifi(), ssid, bssid,
                                      WPASupplicant::kNetworkModeInfrastructure,
                                      frequency, signal_dbm, security_flags);
  }
  WiFiEndpointRefPtr MakeOpenEndpoint(const std::string& ssid,
                                      const std::string& bssid,
                                      uint16_t frequency,
                                      int16_t signal_dbm) {
    return WiFiEndpoint::MakeOpenEndpoint(
        nullptr, wifi(), ssid, bssid, WPASupplicant::kNetworkModeInfrastructure,
        frequency, signal_dbm);
  }
  WiFiEndpointRefPtr MakeOpenEndpointWithWiFi(WiFiRefPtr wifi,
                                              const std::string& ssid,
                                              const std::string& bssid,
                                              uint16_t frequency,
                                              int16_t signal_dbm) {
    return WiFiEndpoint::MakeOpenEndpoint(
        nullptr, wifi, ssid, bssid, WPASupplicant::kNetworkModeInfrastructure,
        frequency, signal_dbm);
  }
  WiFiServiceRefPtr MakeServiceSSID(const std::string& security_class,
                                    const std::string& ssid) {
    const std::vector<uint8_t> ssid_bytes(ssid.begin(), ssid.end());
    return new WiFiService(manager(), &provider_, ssid_bytes, kModeManaged,
                           security_class, WiFiSecurity(), false);
  }
  WiFiServiceRefPtr MakeSimpleService(const std::string& security_class) {
    return new WiFiService(manager(), &provider_, simple_ssid_, kModeManaged,
                           security_class, WiFiSecurity(), false);
  }
  WiFiServiceRefPtr MakeSimpleService(const WiFiSecurity& security) {
    return new WiFiService(manager(), &provider_, simple_ssid_, kModeManaged,
                           WiFiService::ComputeSecurityClass(security),
                           security, false);
  }
  void SetWiFi(WiFiServiceRefPtr service, WiFiRefPtr wifi) {
    service->SetWiFi(wifi);  // Has side-effects.
  }
  void SetWiFiForService(WiFiServiceRefPtr service, WiFiRefPtr wifi) {
    service->wifi_ = wifi;
  }
  WiFiServiceRefPtr MakeServiceWithWiFi(
      const std::string& security_class,
      WiFiSecurity security = WiFiSecurity()) {
    WiFiServiceRefPtr service = security.IsValid()
                                    ? MakeSimpleService(security)
                                    : MakeSimpleService(security_class);
    SetWiFiForService(service, wifi_);
    scoped_refptr<MockProfile> mock_profile(
        new NiceMock<MockProfile>(manager()));
    service->set_profile(mock_profile);
    return service;
  }
  WiFiServiceRefPtr MakeServiceWithMockManager() {
    return new WiFiService(&mock_manager_, &provider_, simple_ssid_,
                           kModeManaged, kSecurityClassNone, WiFiSecurity(),
                           false);
  }
  scoped_refptr<MockWiFi> MakeSimpleWiFi(const std::string& link_name) {
    return new NiceMock<MockWiFi>(manager(), link_name, fake_mac, 0, 0,
                                  new MockWakeOnWiFi());
  }
  ServiceMockAdaptor* GetAdaptor(WiFiService* service) {
    return static_cast<ServiceMockAdaptor*>(service->adaptor());
  }
  Error::Type TestConfigurePassphrase(const std::string& security_class,
                                      const char* passphrase) {
    WiFiServiceRefPtr service = MakeSimpleService(security_class);
    KeyValueStore args;
    if (passphrase) {
      args.Set<std::string>(kPassphraseProperty, passphrase);
    }
    Error error;
    service->Configure(args, &error);
    return error.type();
  }
  bool SortingOrderIs(const WiFiServiceRefPtr& service0,
                      const WiFiServiceRefPtr& service1) {
    bool decision;
    return service0->CompareWithSameTechnology(service1, &decision) && decision;
  }
  scoped_refptr<MockWiFi> wifi() { return wifi_; }
  MockManager* mock_manager() { return &mock_manager_; }
  MockWiFiProvider* provider() { return &provider_; }
  std::string GetAnyDeviceAddress() const {
    return WiFiService::kAnyDeviceAddress;
  }
  const std::vector<uint8_t>& simple_ssid() const { return simple_ssid_; }
  const std::string& simple_ssid_string() const { return simple_ssid_string_; }

  const Metrics::WiFiConnectionAttemptInfo GetConnectionAttemptInfo(
      const WiFiServiceRefPtr& service) const {
    return service->ConnectionAttemptInfo();
  }

  uint64_t GetSessionTag(const WiFiServiceRefPtr& service) const {
    return service->session_tag();
  }

 private:
  MockManager mock_manager_;
  MockNetlinkManager netlink_manager_;
  scoped_refptr<MockWiFi> wifi_;
  MockWiFiProvider provider_;
  const std::vector<uint8_t> simple_ssid_;
  const std::string simple_ssid_string_;
};

// static
const char WiFiServiceTest::fake_mac[] = "AaBBcCDDeeFF";

void SetWiFiProperties(FakeStore* store,
                       const std::string& id,
                       const std::vector<uint8_t>& ssid,
                       const std::string& security_class,
                       WiFiSecurity security = {}) {
  auto hex_ssid = base::HexEncode(ssid.data(), ssid.size());
  store->SetString(id, WiFiService::kStorageType, kTypeWifi);
  store->SetString(id, WiFiService::kStorageSSID, hex_ssid);
  store->SetString(id, WiFiService::kStorageSecurityClass, security_class);
  store->SetString(id, WiFiService::kStorageSecurity, security.ToString());
  store->SetString(id, WiFiService::kStorageMode, kModeManaged);
}

class WiFiServiceSecurityTest : public WiFiServiceTest {
 public:
  // Create a service with a secured endpoint.
  WiFiServiceRefPtr SetupSecureService(const std::string& sec) {
    WiFiSecurity security(sec);
    std::string security_class;

    if (security.IsValid()) {
      security_class = WiFiService::ComputeSecurityClass(security);
    } else {
      EXPECT_TRUE(WiFiService::IsValidSecurityClass(sec))
          << "Invalid security: " << sec;
      security_class = sec;
    }
    WiFiServiceRefPtr service = MakeSimpleService(security_class);

    // For security classes, we don't need an endpoint.
    if (sec == security_class)
      return service;

    // For others, we need an endpoint to help specialize the Service.
    WiFiEndpoint::SecurityFlags flags;
    if (security == WiFiSecurity::kWpa) {
      flags.wpa_psk = true;
    } else if (security == WiFiSecurity::kWpa2) {
      flags.rsn_psk = true;
    } else if (security == WiFiSecurity::kWpa3) {
      flags.rsn_sae = true;
    } else {
      EXPECT_TRUE(false) << sec;
      return nullptr;
    }
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    EXPECT_EQ(security, service->security());
    return service;
  }

  // Test that a service that is created with security |from_security|
  // gets its SecurityClass mapped to |to_security|.
  void TestSecurityMapping(const std::string& from_security,
                           const std::string& to_security_class) {
    WiFiServiceRefPtr wifi_service = SetupSecureService(from_security);
    EXPECT_EQ(to_security_class, wifi_service->security_class());
  }

  // Test whether a service of type |service_security| can load from a
  // storage interface containing an entry for |storage_security_class|.
  // Make sure the result meets |expectation|.  If |expectation| is
  // true, also make sure the service storage identifier changes to
  // match |storage_security_class|.
  bool TestLoadMapping(const std::string& service_security,
                       const std::string& storage_security_class,
                       bool expectation) {
    WiFiServiceRefPtr wifi_service = SetupSecureService(service_security);

    FakeStore store;
    const std::string kStorageId = "storage_id";
    SetWiFiProperties(&store, kStorageId, wifi_service->ssid(),
                      storage_security_class, wifi_service->security());
    bool is_loadable = wifi_service->IsLoadableFrom(store);
    EXPECT_EQ(expectation, is_loadable);
    bool is_loaded = wifi_service->Load(&store);
    EXPECT_EQ(expectation, is_loaded);
    const std::string expected_identifier(expectation ? kStorageId : "");
    EXPECT_EQ(expected_identifier,
              wifi_service->GetLoadableStorageIdentifier(store));

    if (expectation != is_loadable || expectation != is_loaded) {
      return false;
    } else if (!expectation) {
      return true;
    } else {
      return wifi_service->GetStorageIdentifier() == kStorageId;
    }
  }
};

class WiFiServiceUpdateFromEndpointsTest : public WiFiServiceTest {
 public:
  WiFiServiceUpdateFromEndpointsTest()
      : kOkEndpointStrength(WiFiService::SignalToStrength(kOkEndpointSignal)),
        kBadEndpointStrength(WiFiService::SignalToStrength(kBadEndpointSignal)),
        kGoodEndpointStrength(
            WiFiService::SignalToStrength(kGoodEndpointSignal)),
        service(MakeSimpleService(kSecurityClassNone)),
        adaptor(*GetAdaptor(service.get())) {
    ok_endpoint = MakeOpenEndpoint(simple_ssid_string(), kOkEndpointBssId,
                                   kOkEndpointFrequency, kOkEndpointSignal);
    good_endpoint =
        MakeOpenEndpoint(simple_ssid_string(), kGoodEndpointBssId,
                         kGoodEndpointFrequency, kGoodEndpointSignal);
    bad_endpoint = MakeOpenEndpoint(simple_ssid_string(), kBadEndpointBssId,
                                    kBadEndpointFrequency, kBadEndpointSignal);
  }

 protected:
  static const uint16_t kOkEndpointFrequency = 2422;
  static const uint16_t kBadEndpointFrequency = 2417;
  static const uint16_t kGoodEndpointFrequency = 2412;
  static const int16_t kOkEndpointSignal = -60;
  static const int16_t kBadEndpointSignal = -75;
  static const int16_t kGoodEndpointSignal = -50;
  static const char kOkEndpointBssId[];
  static const char kGoodEndpointBssId[];
  static const char kBadEndpointBssId[];
  // Can't be both static and const (because initialization requires a
  // function call). So choose to be just const.
  const uint8_t kOkEndpointStrength;
  const uint8_t kBadEndpointStrength;
  const uint8_t kGoodEndpointStrength;
  WiFiEndpointRefPtr ok_endpoint;
  WiFiEndpointRefPtr bad_endpoint;
  WiFiEndpointRefPtr good_endpoint;
  WiFiServiceRefPtr service;
  ServiceMockAdaptor& adaptor;
};

const char WiFiServiceUpdateFromEndpointsTest::kOkEndpointBssId[] =
    "00:00:00:00:00:01";
const char WiFiServiceUpdateFromEndpointsTest::kGoodEndpointBssId[] =
    "00:00:00:00:00:02";
const char WiFiServiceUpdateFromEndpointsTest::kBadEndpointBssId[] =
    "00:00:00:00:00:03";

TEST_F(WiFiServiceTest, Constructor) {
  const auto histogram = metrics()->GetFullMetricName(
      Metrics::kMetricTimeToJoinMillisecondsSuffix, Technology::kWiFi);
  EXPECT_CALL(*metrics(), AddServiceStateTransitionTimer(
                              _, histogram, Service::kStateAssociating,
                              Service::kStateConfiguring));
  MakeSimpleService(kSecurityClassNone);
}

TEST_F(WiFiServiceTest, StorageId) {
  WiFiServiceRefPtr wifi_service = MakeSimpleService(kSecurityClassNone);
  const auto id = wifi_service->GetStorageIdentifier();
  for (char c : id) {
    EXPECT_TRUE(c == '_' || isxdigit(c) || (isalpha(c) && islower(c)));
  }
  size_t mac_pos = id.find(base::ToLowerASCII(GetAnyDeviceAddress()));
  EXPECT_NE(mac_pos, std::string::npos);
  EXPECT_NE(id.find(std::string(kModeManaged), mac_pos), std::string::npos);
}

TEST_F(WiFiServiceTest, LogName) {
  Service::SetNextSerialNumberForTesting(0);
  WiFiServiceRefPtr wifi_service = MakeSimpleService(kSecurityClassNone);
  EXPECT_EQ("wifi_none_0", wifi_service->log_name());
  wifi_service = MakeSimpleService(kSecurityClassWep);
  EXPECT_EQ("wifi_wep_1", wifi_service->log_name());
  wifi_service = MakeSimpleService(kSecurityClassPsk);
  EXPECT_EQ("wifi_psk_2", wifi_service->log_name());
  wifi_service = MakeSimpleService(kSecurityClass8021x);
  EXPECT_EQ("wifi_802_1x_3", wifi_service->log_name());
}

// Make sure the passphrase is registered as a write only property
// by reading and comparing all string properties returned on the store.
TEST_F(WiFiServiceTest, PassphraseWriteOnly) {
  WiFiServiceRefPtr wifi_service = MakeSimpleService(kSecurityClassPsk);
  brillo::VariantDictionary properties;
  wifi_service->store().GetProperties(&properties, nullptr);
  ASSERT_EQ(properties.find(kPassphraseProperty), properties.end());
}

// Make sure setting the passphrase via D-Bus Service.SetProperty validates
// the passphrase.
TEST_F(WiFiServiceTest, PassphraseSetPropertyValidation) {
  // We only spot check two password cases here to make sure the
  // SetProperty code path does validation.  We're not going to exhaustively
  // test for all types of passwords.
  WiFiServiceRefPtr wifi_service = MakeSimpleService(kSecurityClassWep);
  Error error;
  wifi_service->mutable_store()->SetStringProperty(kPassphraseProperty,
                                                   "0:abcde", &error);
  EXPECT_TRUE(error.IsSuccess());
  wifi_service->mutable_store()->SetStringProperty(kPassphraseProperty,
                                                   "invalid", &error);
  EXPECT_EQ(Error::kInvalidPassphrase, error.type());
}

TEST_F(WiFiServiceTest, PassphraseSetPropertyOpenNetwork) {
  WiFiServiceRefPtr wifi_service = MakeSimpleService(kSecurityClassNone);
  Error error;
  wifi_service->mutable_store()->SetStringProperty(kPassphraseProperty,
                                                   "invalid", &error);
  EXPECT_EQ(Error::kIllegalOperation, error.type());
}

TEST_F(WiFiServiceTest, NonUTF8SSID) {
  std::vector<uint8_t> ssid = {0xff};  // not a valid UTF-8 byte-sequence
  WiFiServiceRefPtr wifi_service =
      new WiFiService(manager(), provider(), ssid, kModeManaged,
                      kSecurityClassNone, WiFiSecurity(), false);
  brillo::VariantDictionary properties;
  // if service doesn't propertly sanitize SSID, this will generate SIGABRT.
  EXPECT_TRUE(wifi_service->store().GetProperties(&properties, nullptr));
}

MATCHER(PSKSecurityArgs, "") {
  return arg.template Contains<std::string>(
             WPASupplicant::kPropertySecurityProtocol) &&
         arg.template Get<std::string>(
             WPASupplicant::kPropertySecurityProtocol) ==
             std::string("WPA RSN") &&
         arg.template Contains<std::string>(
             WPASupplicant::kPropertyPreSharedKey);
}

TEST_F(WiFiServiceTest, ConnectReportBSSes) {
  WiFiEndpointRefPtr endpoint1 =
      MakeOpenEndpoint("a", "00:00:00:00:00:01", 0, 0);
  WiFiEndpointRefPtr endpoint2 =
      MakeOpenEndpoint("a", "00:00:00:00:00:02", 0, 0);
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityClassNone);
  wifi_service->AddEndpoint(endpoint1);
  wifi_service->AddEndpoint(endpoint2);
  EXPECT_CALL(*metrics(), SendToUMA(Metrics::kMetricWifiAvailableBSSes, 2));
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  wifi_service->Connect(nullptr, "in test");
}

TEST_F(WiFiServiceTest, ConnectConditions) {
  Error error;
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityClassNone);
  // With nothing else going on, the service should attempt to connect.
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  wifi_service->Connect(&error, "in test");
  Mock::VerifyAndClearExpectations(wifi().get());

  // But if we're already "connecting" or "connected" then we shouldn't attempt
  // again.
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _)).Times(0);
  wifi_service->SetState(Service::kStateAssociating);
  wifi_service->Connect(&error, "in test");
  wifi_service->SetState(Service::kStateConfiguring);
  wifi_service->Connect(&error, "in test");
  wifi_service->SetState(Service::kStateConnected);
  wifi_service->Connect(&error, "in test");
  wifi_service->SetState(Service::kStateNoConnectivity);
  wifi_service->Connect(&error, "in test");
  wifi_service->SetState(Service::kStateOnline);
  wifi_service->Connect(&error, "in test");
  Mock::VerifyAndClearExpectations(wifi().get());
}

TEST_F(WiFiServiceTest, ConnectTaskPSK) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityClassPsk);
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  SetPassphrase(wifi_service, "0:mumblemumblem");
  wifi_service->Connect(nullptr, "in test");
  EXPECT_THAT(wifi_service->GetSupplicantConfigurationParameters(),
              PSKSecurityArgs());
}

TEST_F(WiFiServiceTest, ConnectTaskRawPMK) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassPsk);
  EXPECT_CALL(*wifi(), ConnectTo(service.get(), _));
  SetPassphrase(service, std::string(IEEE_80211::kWPAHexLen, '1'));
  service->Connect(nullptr, "in test");
  KeyValueStore params = service->GetSupplicantConfigurationParameters();
  EXPECT_FALSE(
      params.Contains<std::string>(WPASupplicant::kPropertyPreSharedKey));
  EXPECT_TRUE(params.Contains<std::vector<uint8_t>>(
      WPASupplicant::kPropertyPreSharedKey));
}

TEST_F(WiFiServiceTest, ConnectTask8021x) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClass8021x);
  service->mutable_eap()->set_identity("identity");
  service->mutable_eap()->set_password("mumble");
  service->OnEapCredentialsChanged(Service::kReasonCredentialsLoaded);
  EXPECT_CALL(*wifi(), ConnectTo(service.get(), _));
  service->Connect(nullptr, "in test");
  KeyValueStore params = service->GetSupplicantConfigurationParameters();
  EXPECT_TRUE(
      params.Contains<std::string>(WPASupplicant::kNetworkPropertyEapIdentity));
  EXPECT_TRUE(
      params.Contains<std::string>(WPASupplicant::kNetworkPropertyCaPath));
}

TEST_F(WiFiServiceTest, ConnectTask8021xWithMockEap) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClass8021x);
  MockEapCredentials* eap = SetMockEap(service);
  EXPECT_CALL(*eap, IsConnectable()).WillOnce(Return(true));
  EXPECT_CALL(*wifi(), ConnectTo(service.get(), _));
  service->OnEapCredentialsChanged(Service::kReasonCredentialsLoaded);
  service->Connect(nullptr, "in test");

  EXPECT_CALL(*eap, PopulateSupplicantProperties(_, _));
  // The mocked function does not actually set EAP parameters so we cannot
  // expect them to be set.
  service->GetSupplicantConfigurationParameters();
}

MATCHER_P(WEPSecurityArgsKeyIndex, index, "") {
  uint32_t index_u32 = index;
  return arg.template Contains<std::string>(WPASupplicant::kPropertyAuthAlg) &&
         arg.template Contains<std::vector<uint8_t>>(
             WPASupplicant::kPropertyWEPKey + base::NumberToString(index)) &&
         arg.template Contains<uint32_t>(
             WPASupplicant::kPropertyWEPTxKeyIndex) &&
         (arg.template Get<uint32_t>(WPASupplicant::kPropertyWEPTxKeyIndex) ==
          index_u32);
}

TEST_F(WiFiServiceTest, ConnectTaskWEP) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityClassWep);
  SetPassphrase(wifi_service, "0:abcdefghijklm");
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  wifi_service->Connect(nullptr, "in test");
  EXPECT_THAT(wifi_service->GetSupplicantConfigurationParameters(),
              WEPSecurityArgsKeyIndex(0));

  SetPassphrase(wifi_service, "abcdefghijklm");
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  wifi_service->Connect(nullptr, "in test");
  EXPECT_THAT(wifi_service->GetSupplicantConfigurationParameters(),
              WEPSecurityArgsKeyIndex(0));

  SetPassphrase(wifi_service, "1:abcdefghijklm");
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  wifi_service->Connect(nullptr, "in test");
  EXPECT_THAT(wifi_service->GetSupplicantConfigurationParameters(),
              WEPSecurityArgsKeyIndex(1));

  SetPassphrase(wifi_service, "2:abcdefghijklm");
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  wifi_service->Connect(nullptr, "in test");
  EXPECT_THAT(wifi_service->GetSupplicantConfigurationParameters(),
              WEPSecurityArgsKeyIndex(2));

  SetPassphrase(wifi_service, "3:abcdefghijklm");
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  wifi_service->Connect(nullptr, "in test");
  EXPECT_THAT(wifi_service->GetSupplicantConfigurationParameters(),
              WEPSecurityArgsKeyIndex(3));
}

// Dynamic WEP + 802.1x.
TEST_F(WiFiServiceTest, ConnectTaskDynamicWEP) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityClassWep);

  wifi_service->mutable_eap()->SetKeyManagement("IEEE8021X", nullptr);
  wifi_service->mutable_eap()->set_identity("something");
  wifi_service->mutable_eap()->set_password("mumble");
  wifi_service->OnEapCredentialsChanged(Service::kReasonCredentialsLoaded);
  EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
  wifi_service->Connect(nullptr, "in test");
  KeyValueStore params = wifi_service->GetSupplicantConfigurationParameters();
  EXPECT_TRUE(
      params.Contains<std::string>(WPASupplicant::kNetworkPropertyEapIdentity));
  EXPECT_TRUE(
      params.Contains<std::string>(WPASupplicant::kNetworkPropertyCaPath));
  EXPECT_FALSE(
      params.Contains<std::string>(WPASupplicant::kPropertySecurityProtocol));
}

TEST_F(WiFiServiceTest, ConnectTaskFT) {
  {
    WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityClassPsk);
#if !defined(DISABLE_WPA3_SAE)
    std::string ft_key_mgmt = "WPA-PSK WPA-PSK-SHA256 SAE FT-PSK FT-SAE";
    std::string noft_key_mgmt = "WPA-PSK WPA-PSK-SHA256 SAE";
#else
    std::string ft_key_mgmt = "WPA-PSK WPA-PSK-SHA256 FT-PSK";
    std::string noft_key_mgmt = "WPA-PSK WPA-PSK-SHA256";
#endif  // DISABLE_WPA3_SAE

    wifi_service->Connect(nullptr, "in test");
    KeyValueStore params = wifi_service->GetSupplicantConfigurationParameters();
    EXPECT_EQ(ft_key_mgmt,
              params.Get<std::string>(
                  WPASupplicant::kNetworkPropertyEapKeyManagement));

    manager()->props_.ft_enabled = false;
    wifi_service->Connect(nullptr, "in test");
    params = wifi_service->GetSupplicantConfigurationParameters();
    EXPECT_EQ(noft_key_mgmt,
              params.Get<std::string>(
                  WPASupplicant::kNetworkPropertyEapKeyManagement));

    manager()->props_.ft_enabled = true;
    wifi_service->Connect(nullptr, "in test");
    params = wifi_service->GetSupplicantConfigurationParameters();
    EXPECT_EQ(ft_key_mgmt,
              params.Get<std::string>(
                  WPASupplicant::kNetworkPropertyEapKeyManagement));
  }
  {
    WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityClass8021x);
    wifi_service->mutable_eap()->set_identity("identity");
    wifi_service->mutable_eap()->set_password("mumble");
    wifi_service->OnEapCredentialsChanged(Service::kReasonCredentialsLoaded);

    manager()->props_.ft_enabled = std::nullopt;
    wifi_service->Connect(nullptr, "in test");
    KeyValueStore params = wifi_service->GetSupplicantConfigurationParameters();
    std::string default_key_mgmt = "WPA-EAP WPA-EAP-SHA256 FT-EAP";
    EXPECT_EQ(default_key_mgmt,
              params.Get<std::string>(
                  WPASupplicant::kNetworkPropertyEapKeyManagement));

    manager()->props_.ft_enabled = false;
    wifi_service->Connect(nullptr, "in test");
    params = wifi_service->GetSupplicantConfigurationParameters();
    EXPECT_EQ("WPA-EAP WPA-EAP-SHA256",
              params.Get<std::string>(
                  WPASupplicant::kNetworkPropertyEapKeyManagement));

    manager()->props_.ft_enabled = true;
    wifi_service->Connect(nullptr, "in test");
    params = wifi_service->GetSupplicantConfigurationParameters();
    EXPECT_EQ(default_key_mgmt,
              params.Get<std::string>(
                  WPASupplicant::kNetworkPropertyEapKeyManagement));
  }
}

TEST_F(WiFiServiceTest, ConnectTaskBSSIDAllowlist) {
  {
    WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityClassNone);
    EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));
    wifi_service->Connect(nullptr, "in test");

    // If the BSSID allowlist didn't change, the field won't be set in the
    // supplicant params
    KeyValueStore params = wifi_service->GetSupplicantConfigurationParameters();
    EXPECT_FALSE(params.Contains<std::string>(
        WPASupplicant::kNetworkPropertyBSSIDAccept));
  }

  {
    Error error;
    WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityClassNone);

    // The duped bssid's should get filtered out before we pass it to WPA
    // supplicant.
    std::vector<std::string> duped_bssid_allowlist = {
        "00:00:00:00:00:01", "00:00:00:00:00:01", "00:00:00:00:00:02"};
    std::vector<std::string> not_duped_bssid_allowlist = {"00:00:00:00:00:01",
                                                          "00:00:00:00:00:02"};
    EXPECT_CALL(*wifi(), SetBSSIDAllowlist(_, not_duped_bssid_allowlist, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*wifi(), ConnectTo(wifi_service.get(), _));

    EXPECT_TRUE(wifi_service->SetBSSIDAllowlist(duped_bssid_allowlist, &error));
    wifi_service->Connect(nullptr, "in test");
    KeyValueStore params = wifi_service->GetSupplicantConfigurationParameters();
    EXPECT_EQ(
        "00:00:00:00:00:01 00:00:00:00:00:02",
        params.Get<std::string>(WPASupplicant::kNetworkPropertyBSSIDAccept));
  }
}

TEST_F(WiFiServiceTest, SetPassphraseResetHasEverConnected) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityClassPsk);
  const std::string kPassphrase = "abcdefgh";

  // A changed passphrase should reset has_ever_connected_ field.
  wifi_service->has_ever_connected_ = true;
  EXPECT_TRUE(wifi_service->has_ever_connected());
  SetPassphrase(wifi_service, kPassphrase);
  EXPECT_FALSE(wifi_service->has_ever_connected());
}

TEST_F(WiFiServiceTest, SetPassphraseRemovesCachedCredentials) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityClassPsk);

  const std::string kPassphrase = "abcdefgh";

  {
    // A changed passphrase should trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(wifi_service.get()));
    EXPECT_TRUE(SetPassphrase(wifi_service, kPassphrase));
    Mock::VerifyAndClearExpectations(wifi().get());
  }

  {
    // An unchanged passphrase should not trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(_)).Times(0);
    EXPECT_TRUE(SetPassphrase(wifi_service, kPassphrase));
    Mock::VerifyAndClearExpectations(wifi().get());
  }

  {
    // A modified passphrase should trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(wifi_service.get()));
    EXPECT_TRUE(SetPassphrase(wifi_service, kPassphrase + "X"));
    Mock::VerifyAndClearExpectations(wifi().get());
  }

  {
    Error error;
    // A cleared passphrase should also trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(wifi_service.get()));
    wifi_service->ClearPassphrase(&error);
    Mock::VerifyAndClearExpectations(wifi().get());
    EXPECT_TRUE(error.IsSuccess());
  }

  {
    // An invalid passphrase should not trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(_)).Times(0);
    EXPECT_FALSE(SetPassphrase(wifi_service, ""));
    Mock::VerifyAndClearExpectations(wifi().get());
  }

  {
    // A change to EAP parameters in a PSK (non 802.1x) service will not
    // trigger cache removal.
    wifi_service->has_ever_connected_ = true;
    EXPECT_TRUE(wifi_service->has_ever_connected());
    EXPECT_CALL(*wifi(), ClearCachedCredentials(wifi_service.get())).Times(0);
    wifi_service->OnEapCredentialsChanged(Service::kReasonPropertyUpdate);
    EXPECT_TRUE(wifi_service->has_ever_connected());
    Mock::VerifyAndClearExpectations(wifi().get());
  }

  WiFiServiceRefPtr eap_wifi_service = MakeServiceWithWiFi(kSecurityClass8021x);

  {
    // Any change to EAP parameters (including a null one) will trigger cache
    // removal in an 802.1x service.  This is a lot less granular than the
    // passphrase checks above.
    // Changes in EAP parameters should also clear has_ever_connected_.
    eap_wifi_service->has_ever_connected_ = true;
    EXPECT_TRUE(eap_wifi_service->has_ever_connected());
    EXPECT_CALL(*wifi(), ClearCachedCredentials(eap_wifi_service.get()));
    eap_wifi_service->OnEapCredentialsChanged(Service::kReasonPropertyUpdate);
    EXPECT_FALSE(eap_wifi_service->has_ever_connected());
    Mock::VerifyAndClearExpectations(wifi().get());
  }
}

// This test is somewhat redundant, since:
//
// a) we test that generic property setters return false on a null
//    change (e.g. in PropertyAccessorTest.SignedIntCorrectness)
// b) we test that custom EAP property setters return false on a null
//    change in EapCredentialsTest.CustomSetterNoopChange
// c) we test that the various custom accessors pass through the
//    return value of custom setters
//    (e.g. PropertyAccessorTest.CustomAccessorCorrectness)
// d) we test that PropertyStore skips the change callback when a
//    property setter return false (PropertyStoreTypedTest.SetProperty)
//
// Nonetheless, I think it's worth testing the WiFi+EAP case directly.
TEST_F(WiFiServiceTest, EapAuthPropertyChangeClearsCachedCredentials) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityClass8021x);
  PropertyStore& property_store(*wifi_service->mutable_store());

  // Property with custom accessor.
  const std::string kPassword = "abcdefgh";
  {
    Error error;
    // A changed passphrase should trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(wifi_service.get()));
    property_store.SetStringProperty(kEapPasswordProperty, kPassword, &error);
    EXPECT_TRUE(error.IsSuccess());
    Mock::VerifyAndClearExpectations(wifi().get());
  }
  {
    Error error;
    // An unchanged passphrase should not trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(_)).Times(0);
    property_store.SetStringProperty(kEapPasswordProperty, kPassword, &error);
    EXPECT_TRUE(error.IsSuccess());
    Mock::VerifyAndClearExpectations(wifi().get());
  }
  {
    Error error;
    // A modified passphrase should trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(wifi_service.get()));
    property_store.SetStringProperty(kEapPasswordProperty, kPassword + "X",
                                     &error);
    EXPECT_TRUE(error.IsSuccess());
    Mock::VerifyAndClearExpectations(wifi().get());
  }

  // Property with generic accessor.
  const std::string kCertId = "abcdefgh";
  {
    Error error;
    // A changed cert id should trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(wifi_service.get()));
    property_store.SetStringProperty(kEapCertIdProperty, kCertId, &error);
    EXPECT_TRUE(error.IsSuccess());
    Mock::VerifyAndClearExpectations(wifi().get());
  }
  {
    Error error;
    // An unchanged cert id should not trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(_)).Times(0);
    property_store.SetStringProperty(kEapCertIdProperty, kCertId, &error);
    EXPECT_TRUE(error.IsSuccess());
    Mock::VerifyAndClearExpectations(wifi().get());
  }
  {
    Error error;
    // A modified cert id should trigger cache removal.
    EXPECT_CALL(*wifi(), ClearCachedCredentials(wifi_service.get()));
    property_store.SetStringProperty(kEapCertIdProperty, kCertId + "X", &error);
    EXPECT_TRUE(error.IsSuccess());
    Mock::VerifyAndClearExpectations(wifi().get());
  }
}

TEST_F(WiFiServiceTest, LoadHidden) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);
  ASSERT_FALSE(service->hidden_ssid_);
  FakeStore store;
  const std::string storage_id = service->GetStorageIdentifier();
  SetWiFiProperties(&store, storage_id, simple_ssid(), kSecurityClassNone);
  store.SetBool(storage_id, WiFiService::kStorageHiddenSSID, true);
  EXPECT_TRUE(service->Load(&store));
  EXPECT_TRUE(service->hidden_ssid_);
}

TEST_F(WiFiServiceTest, LoadMACPolicy) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);
  EXPECT_EQ(service->random_mac_policy_,
            WiFiService::RandomizationPolicy::Hardware);
  FakeStore store;
  const std::string storage_id = service->GetStorageIdentifier();
  SetWiFiProperties(&store, storage_id, simple_ssid(), kSecurityClassNone);
  store.SetString(storage_id, WiFiService::kStorageMACPolicy,
                  kWifiRandomMacPolicyPersistentRandom);
  service->mac_address_.Randomize();
  auto mac_value = service->mac_address_.ToString();
  service->mac_address_.Save(&store, storage_id);
  // Re-randomize to check if previous value is restored.
  service->mac_address_.Randomize();
  EXPECT_TRUE(service->Load(&store));
  // After loading of the service from profile policy should reflect stored
  // value and subsequent call to UpdateMACAddress() should indicate no change.
  EXPECT_EQ(service->random_mac_policy_,
            WiFiService::RandomizationPolicy::PersistentRandom);
  EXPECT_EQ(mac_value, service->mac_address_.ToString());
  auto [mac, policy_change] = service->UpdateMACAddress();
  EXPECT_TRUE(mac.empty());
  EXPECT_FALSE(policy_change);
}

TEST_F(WiFiServiceTest, SetPassphraseForNonPassphraseService) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);
  FakeStore store;
  const std::string storage_id = service->GetStorageIdentifier();
  SetWiFiProperties(&store, storage_id, simple_ssid(), kSecurityClassNone);

  EXPECT_TRUE(service->Load(&store));
  Error error;
  EXPECT_FALSE(service->SetPassphrase("password", &error));
  EXPECT_TRUE(error.type() == Error::kIllegalOperation);
}

TEST_F(WiFiServiceTest, LoadMultipleMatchingGroups) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  std::string storage_id0 = "id0";
  std::string storage_id1 = "id1";
  FakeStore store;
  SetWiFiProperties(&store, storage_id0, simple_ssid(), kSecurityClassNone);
  SetWiFiProperties(&store, storage_id1, simple_ssid(), kSecurityClassNone);
  EXPECT_TRUE(service->Load(&store));
  EXPECT_EQ(service->GetStorageIdentifier(), storage_id0);
}

TEST_F(WiFiServiceSecurityTest, WPAMapping) {
  TestSecurityMapping(kSecurityWpa3, kSecurityClassPsk);
  TestSecurityMapping(kSecurityWpa2, kSecurityClassPsk);
  TestSecurityMapping(kSecurityWpa, kSecurityClassPsk);
  TestSecurityMapping(kSecurityClassPsk, kSecurityClassPsk);
  TestSecurityMapping(kSecurityWep, kSecurityClassWep);
  TestSecurityMapping(kSecurityNone, kSecurityClassNone);
  TestSecurityMapping(kSecurityClass8021x, kSecurityClass8021x);
}

TEST_F(WiFiServiceSecurityTest, LoadMapping) {
  EXPECT_TRUE(TestLoadMapping(kSecurityWpa3, kSecurityClassPsk, true));
  EXPECT_TRUE(TestLoadMapping(kSecurityWpa2, kSecurityClassPsk, true));
  EXPECT_TRUE(TestLoadMapping(kSecurityWpa, kSecurityClassPsk, true));
  EXPECT_TRUE(TestLoadMapping(kSecurityWep, kSecurityClassWep, true));
  EXPECT_TRUE(TestLoadMapping(kSecurityWep, kSecurityClassPsk, false));
}

TEST_F(WiFiServiceSecurityTest, EndpointsDisappear) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassPsk);
  WiFiEndpoint::SecurityFlags flags;
  flags.rsn_psk = true;
  WiFiEndpointRefPtr endpoint =
      MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
  service->AddEndpoint(endpoint);
  EXPECT_EQ(WiFiSecurity::kWpa2, service->security());
  EXPECT_EQ(kSecurityClassPsk, service->security_class());

  service->RemoveEndpoint(endpoint);
  // Security is sticky.
  EXPECT_EQ(WiFiSecurity::kWpa2, service->security());
  EXPECT_EQ(kSecurityClassPsk, service->security_class());
}

TEST_F(WiFiServiceTest, LoadAndUnloadPassphrase) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassPsk);
  FakeStore store;
  const std::string kStorageId = service->GetStorageIdentifier();
  SetWiFiProperties(&store, kStorageId, simple_ssid(), kSecurityClassPsk);
  const std::string kPassphrase = "passphrase";
  store.SetString(kStorageId, WiFiService::kStorageCredentialPassphrase,
                  kPassphrase);
  EXPECT_TRUE(service->need_passphrase_);
  EXPECT_TRUE(service->Load(&store));
  EXPECT_EQ(kPassphrase, service->passphrase_);
  EXPECT_TRUE(service->connectable());
  EXPECT_FALSE(service->need_passphrase_);
  service->Unload();
  EXPECT_EQ(std::string(""), service->passphrase_);
  EXPECT_FALSE(service->connectable());
  EXPECT_TRUE(service->need_passphrase_);
}

TEST_F(WiFiServiceTest, LoadPassphraseClearCredentials) {
  const std::string kOldPassphrase = "oldpassphrase";
  const std::string kPassphrase = "passphrase";

  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassPsk);
  FakeStore store;
  const std::string kStorageId = service->GetStorageIdentifier();
  SetWiFiProperties(&store, kStorageId, simple_ssid(), kSecurityClassPsk);
  store.SetString(kStorageId, WiFiService::kStorageCredentialPassphrase,
                  kPassphrase);
  store.SetBool(kStorageId, Service::kStorageHasEverConnected, true);

  // Set old passphrase for service
  EXPECT_TRUE(service->need_passphrase_);
  service->passphrase_ = kOldPassphrase;
  service->has_ever_connected_ = true;

  scoped_refptr<MockProfile> mock_profile =
      static_cast<MockProfile*>(service->profile().get());
  // Detect if the service is going to attempt to update the stored profile.
  EXPECT_CALL(*mock_profile, GetConstStorage()).Times(0);

  // The kOldPassphrase is different than the newly loaded passhprase,
  // so the credentials should be cleared.
  EXPECT_CALL(*wifi(), ClearCachedCredentials(_)).Times(1);
  EXPECT_CALL(*mock_profile, UpdateService(_)).Times(0);
  EXPECT_TRUE(service->Load(&store));
  EXPECT_EQ(kPassphrase, service->passphrase_);
  EXPECT_TRUE(service->has_ever_connected_);

  Mock::VerifyAndClearExpectations(wifi().get());
  Mock::VerifyAndClearExpectations(mock_profile.get());

  // Repeat Service::Load with same old and new passphrase. Since the old
  // and new passphrase match, verify the cache is not cleared during
  // profile load.
  service->set_profile(mock_profile);
  EXPECT_CALL(*mock_profile, GetConstStorage()).Times(0);
  EXPECT_CALL(*wifi(), ClearCachedCredentials(_)).Times(0);
  EXPECT_TRUE(service->Load(&store));
  EXPECT_EQ(kPassphrase, service->passphrase_);
  EXPECT_TRUE(service->has_ever_connected_);
}

TEST_F(WiFiServiceTest, LoadWithPasspointCredentials) {
  const std::string creds_id("an_id");
  const uint64_t match_priority = 3;
  PasspointCredentialsRefPtr credentials = new PasspointCredentials(creds_id);
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);

  FakeStore store;
  const std::string storage_id = service->GetStorageIdentifier();
  SetWiFiProperties(&store, storage_id, simple_ssid(), kSecurityClassNone);

  // No credentials stored.
  EXPECT_TRUE(service->Load(&store));
  EXPECT_EQ(nullptr, service->parent_credentials());

  // Set of credentials in the store.
  store.SetString(storage_id, WiFiService::kStoragePasspointCredentials,
                  creds_id);
  store.SetUint64(storage_id, WiFiService::kStoragePasspointMatchPriority,
                  match_priority);
  EXPECT_CALL(*provider(), FindCredentials(creds_id))
      .WillOnce(Return(credentials));
  EXPECT_TRUE(service->Load(&store));
  EXPECT_EQ(credentials, service->parent_credentials());
  EXPECT_EQ(match_priority, service->match_priority());

  // Set of credentials in the store, but not in the provider
  EXPECT_CALL(*provider(), FindCredentials(creds_id)).WillOnce(Return(nullptr));
  EXPECT_FALSE(service->Load(&store));
}

TEST_F(WiFiServiceTest, ConfigureMakesConnectable) {
  std::string guid("legit_guid");
  KeyValueStore args;
  args.Set<std::string>(kEapIdentityProperty, "legit_identity");
  args.Set<std::string>(kEapPasswordProperty, "legit_password");
  args.Set<std::string>(kEapMethodProperty, "PEAP");
  args.Set<std::string>(kGuidProperty, guid);
  Error error;

  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClass8021x);
  // Hack the GUID in so that we don't have to mess about with WiFi to register
  // our service.  This way, Manager will handle the lookup itself.
  service->SetGuid(guid, nullptr);
  manager()->RegisterService(service);
  EXPECT_FALSE(service->connectable());
  EXPECT_EQ(service, manager()->GetService(args, &error));
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_TRUE(service->connectable());
}

TEST_F(WiFiServiceTest, ConfigurePassphrase) {
  EXPECT_EQ(Error::kIllegalOperation,
            TestConfigurePassphrase(kSecurityClassNone, ""));
  EXPECT_EQ(Error::kIllegalOperation,
            TestConfigurePassphrase(kSecurityClassNone, "foo"));
  EXPECT_EQ(Error::kSuccess,
            TestConfigurePassphrase(kSecurityClassWep, nullptr));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(kSecurityClassWep, ""));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(kSecurityClassWep, "abcd"));
  EXPECT_EQ(Error::kSuccess,
            TestConfigurePassphrase(kSecurityClassWep, "abcde"));
  EXPECT_EQ(Error::kSuccess,
            TestConfigurePassphrase(kSecurityClassWep, "abcdefghijklm"));
  EXPECT_EQ(Error::kSuccess,
            TestConfigurePassphrase(kSecurityClassWep, "0:abcdefghijklm"));
  EXPECT_EQ(Error::kSuccess,
            TestConfigurePassphrase(kSecurityClassWep, "0102030405"));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(kSecurityClassWep, "0x0102030405"));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(kSecurityClassWep, "O102030405"));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(kSecurityClassWep, "1:O102030405"));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(kSecurityClassWep, "1:0xO102030405"));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(kSecurityClassWep, "0xO102030405"));
  EXPECT_EQ(
      Error::kSuccess,
      TestConfigurePassphrase(kSecurityClassWep, "0102030405060708090a0b0c0d"));
  EXPECT_EQ(
      Error::kSuccess,
      TestConfigurePassphrase(kSecurityClassWep, "0102030405060708090A0B0C0D"));
  EXPECT_EQ(Error::kSuccess,
            TestConfigurePassphrase(kSecurityClassWep,
                                    "0:0102030405060708090a0b0c0d"));
  EXPECT_EQ(Error::kSuccess,
            TestConfigurePassphrase(kSecurityClassWep,
                                    "0:0x0102030405060708090a0b0c0d"));
  EXPECT_EQ(Error::kSuccess,
            TestConfigurePassphrase(kSecurityClassPsk, nullptr));
  EXPECT_EQ(Error::kSuccess,
            TestConfigurePassphrase(kSecurityClassPsk, "secure password"));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(kSecurityClassPsk, ""));
  EXPECT_EQ(Error::kSuccess,
            TestConfigurePassphrase(
                kSecurityClassPsk,
                std::string(IEEE_80211::kWPAAsciiMinLen, 'Z').c_str()));
  EXPECT_EQ(Error::kSuccess,
            TestConfigurePassphrase(
                kSecurityClassPsk,
                std::string(IEEE_80211::kWPAAsciiMaxLen, 'Z').c_str()));
  // subtle: invalid length for hex key, but valid as ascii passphrase
  EXPECT_EQ(Error::kSuccess,
            TestConfigurePassphrase(
                kSecurityClassPsk,
                std::string(IEEE_80211::kWPAHexLen - 1, '1').c_str()));
  EXPECT_EQ(
      Error::kSuccess,
      TestConfigurePassphrase(
          kSecurityClassPsk, std::string(IEEE_80211::kWPAHexLen, '1').c_str()));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(
                kSecurityClassPsk,
                std::string(IEEE_80211::kWPAAsciiMinLen - 1, 'Z').c_str()));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(
                kSecurityClassPsk,
                std::string(IEEE_80211::kWPAAsciiMaxLen + 1, 'Z').c_str()));
  EXPECT_EQ(Error::kInvalidPassphrase,
            TestConfigurePassphrase(
                kSecurityClassPsk,
                std::string(IEEE_80211::kWPAHexLen + 1, '1').c_str()));
}

TEST_F(WiFiServiceTest, ConfigureRedundantProperties) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);
  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  args.Set<std::string>(kSSIDProperty, simple_ssid_string());
  args.Set<std::string>(kWifiHexSsid,
                        "This is ignored even if it is invalid hex.");
  const std::string kGUID = "aguid";
  args.Set<std::string>(kGuidProperty, kGUID);

  EXPECT_EQ("", service->guid());
  Error error;
  service->Configure(args, &error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(kGUID, service->guid());
}

TEST_F(WiFiServiceTest, SetRoamState) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  service->SetRoamState(Service::kRoamStateConnected);
  EXPECT_EQ(Service::kRoamStateConnected, service->roam_state());
  service->SetState(Service::kStateConnected);
  EXPECT_EQ(Service::kRoamStateIdle, service->roam_state());
}

TEST_F(WiFiServiceTest, DisconnectWithWiFi) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassWep);
  // An inactive Service will not have OnDisconnected triggered.
  service->SetState(Service::kStateConnected);
  EXPECT_CALL(*wifi(), IsCurrentService(service.get())).WillOnce(Return(true));
  EXPECT_CALL(*wifi(), DisconnectFrom(service.get())).Times(1);
  Error error;
  service->Disconnect(&error, "in test");
}

TEST_F(WiFiServiceTest, DisconnectWithoutWiFi) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassWep);
  EXPECT_CALL(*wifi(), DisconnectFrom(_)).Times(0);
  service->SetState(Service::kStateAssociating);
  Error error;
  service->Disconnect(&error, "in test");
  EXPECT_EQ(Error::kOperationFailed, error.type());
}

TEST_F(WiFiServiceTest, DisconnectWithoutWiFiWhileAssociating) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassWep);
  EXPECT_CALL(*wifi(), DisconnectFrom(_)).Times(0);
  service->SetState(Service::kStateAssociating);
  ScopedMockLog log;
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(log, Log(logging::LOGGING_ERROR, _,
                       HasSubstr("WiFi endpoints do not (yet) exist.")));
  Error error;
  service->Disconnect(&error, "in test");
  EXPECT_EQ(Error::kOperationFailed, error.type());
}

TEST_F(WiFiServiceTest, UnloadAndClearCacheWEP) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassWep);
  // An inactive Service will not have OnDisconnected triggered.
  service->SetState(Service::kStateConnected);
  EXPECT_CALL(*wifi(), IsCurrentService(service.get())).WillOnce(Return(true));
  EXPECT_CALL(*wifi(), ClearCachedCredentials(service.get())).Times(1);
  EXPECT_CALL(*wifi(), DisconnectFrom(service.get())).Times(1);
  service->Unload();
}

TEST_F(WiFiServiceTest, UnloadAndClearCache8021x) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClass8021x);
  // An inactive Service will not have OnDisconnected triggered.
  service->SetState(Service::kStateConnected);
  EXPECT_CALL(*wifi(), IsCurrentService(service.get())).WillOnce(Return(true));
  EXPECT_CALL(*wifi(), ClearCachedCredentials(service.get())).Times(1);
  EXPECT_CALL(*wifi(), DisconnectFrom(service.get())).Times(1);
  service->Unload();
}

TEST_F(WiFiServiceTest, Connectable) {
  // Open network should be connectable.
  EXPECT_TRUE(CheckConnectable(kSecurityClassNone, nullptr, false));

  // Open network should remain connectable if we try to set a password on it.
  EXPECT_TRUE(CheckConnectable(kSecurityClassNone, "abcde", false));

  // WEP network with passphrase set should be connectable.
  EXPECT_TRUE(CheckConnectable(kSecurityClassWep, "abcde", false));

  // WEP network without passphrase set should NOT be connectable.
  EXPECT_FALSE(CheckConnectable(kSecurityClassWep, nullptr, false));

  // A bad passphrase should not make a WEP network connectable.
  EXPECT_FALSE(CheckConnectable(kSecurityClassWep, "a", false));

  // Similar to WEP, for PSK.
  EXPECT_TRUE(CheckConnectable(kSecurityClassPsk, "abcdefgh", false));
  EXPECT_FALSE(CheckConnectable(kSecurityClassPsk, nullptr, false));
  EXPECT_FALSE(CheckConnectable(kSecurityClassPsk, "a", false));

  // 802.1x without connectable EAP credentials should NOT be connectable.
  EXPECT_FALSE(CheckConnectable(kSecurityClass8021x, nullptr, false));

  // 802.1x with connectable EAP credentials should be connectable.
  EXPECT_TRUE(CheckConnectable(kSecurityClass8021x, nullptr, true));

  // Dynamic WEP + 802.1X should be connectable under the same conditions.
  EXPECT_TRUE(CheckConnectable(kSecurityClassWep, nullptr, true));

  {
    WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassPsk);
    SetPassphrase(service, "abcdefgh");
    WiFiEndpoint::SecurityFlags flags;
    flags.rsn_psk = true;
    flags.rsn_sae = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    // WPA3-transitional; all devices should support.
    EXPECT_TRUE(service->connectable());
  }
  {
    WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassPsk);
    SetPassphrase(service, "abcdefgh");
    WiFiEndpoint::SecurityFlags flags;
    flags.rsn_sae = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    EXPECT_EQ(service->security(), WiFiSecurity::kWpa3);
    // WPA3-only; match device support.
    EXPECT_EQ(wifi()->SupportsWPA3(), service->connectable());
    // Switch to transitional mode - if we only have WPA3 endpoints then we
    // should still match device support for WPA3.
    service->security_ = WiFiSecurity::kWpa2Wpa3;
    EXPECT_EQ(wifi()->SupportsWPA3(), service->connectable());
  }
}

TEST_F(WiFiServiceTest, IsAutoConnectable) {
  const char* reason;
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);
  EXPECT_CALL(*wifi(), IsIdle()).WillRepeatedly(Return(true));
  EXPECT_FALSE(service->HasEndpoints());
  EXPECT_FALSE(service->IsAutoConnectable(&reason));
  EXPECT_STREQ(WiFiService::kAutoConnMediumUnavailable, reason);

  reason = "";
  WiFiEndpointRefPtr endpoint =
      MakeOpenEndpoint("a", "00:00:00:00:00:01", 0, 0);
  service->AddEndpoint(endpoint);
  EXPECT_CALL(*wifi(), IsIdle()).WillRepeatedly(Return(true));
  EXPECT_TRUE(service->HasEndpoints());
  EXPECT_TRUE(service->IsAutoConnectable(&reason));
  EXPECT_STREQ("", reason);

  // WiFi only supports connecting to one Service at a time. So, to
  // avoid disrupting connectivity, we only allow auto-connection to
  // a WiFiService when the corresponding WiFi is idle.
  EXPECT_CALL(*wifi(), IsIdle()).WillRepeatedly(Return(false));
  EXPECT_TRUE(service->HasEndpoints());
  EXPECT_FALSE(service->IsAutoConnectable(&reason));
  EXPECT_STREQ(WiFiService::kAutoConnBusy, reason);
}

TEST_F(WiFiServiceTest, AutoConnect) {
  const char* reason;
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);
  EXPECT_FALSE(service->IsAutoConnectable(&reason));
  EXPECT_CALL(*wifi(), ConnectTo(_, _)).Times(0);
  service->AutoConnect();
  dispatcher()->DispatchPendingEvents();

  WiFiEndpointRefPtr endpoint =
      MakeOpenEndpoint("a", "00:00:00:00:00:01", 0, 0);
  service->AddEndpoint(endpoint);
  EXPECT_CALL(*wifi(), IsIdle()).WillRepeatedly(Return(true));
  EXPECT_TRUE(service->IsAutoConnectable(&reason));
  EXPECT_CALL(*wifi(), ConnectTo(_, _));
  service->AutoConnect();
  dispatcher()->DispatchPendingEvents();

  Error error;
  service->UserInitiatedDisconnect("RPC", &error);
  dispatcher()->DispatchPendingEvents();
  EXPECT_FALSE(service->IsAutoConnectable(&reason));
}

TEST_F(WiFiServiceTest, PreferWPA2OverWPA) {
  std::string ssid0 = "a", ssid1 = "b";
  WiFiServiceRefPtr service0 = MakeServiceSSID(kSecurityClassPsk, ssid0);
  WiFiServiceRefPtr service1 = MakeServiceSSID(kSecurityClassPsk, ssid1);

  WiFiEndpoint::SecurityFlags rsn_flags;
  rsn_flags.rsn_psk = true;
  WiFiEndpoint::SecurityFlags wpa_flags;
  wpa_flags.wpa_psk = true;
  WiFiEndpointRefPtr rsn_endpoint =
      MakeEndpoint(ssid0, "00:00:00:00:00:01", 0, 0, rsn_flags);
  WiFiEndpointRefPtr wpa_endpoint =
      MakeEndpoint(ssid1, "00:00:00:00:00:02", 0, 0, wpa_flags);
  service0->AddEndpoint(rsn_endpoint);
  service1->AddEndpoint(wpa_endpoint);

  EXPECT_EQ(WiFiSecurity::kWpa2, service0->security());
  EXPECT_EQ(WiFiSecurity::kWpa, service1->security());

  const auto& ret =
      Service::Compare(service0, service1, false, std::vector<Technology>());
  EXPECT_TRUE(ret.first);
}

TEST_F(WiFiServiceTest, ClearWriteOnlyDerivedProperty) {
  WiFiServiceRefPtr wifi_service = MakeSimpleService(kSecurityClassWep);

  EXPECT_EQ("", wifi_service->passphrase_);

  Error error;
  const std::string kPassphrase = "0:abcde";
  wifi_service->mutable_store()->SetAnyProperty(
      kPassphraseProperty, brillo::Any(kPassphrase), &error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(kPassphrase, wifi_service->passphrase_);

  EXPECT_TRUE(wifi_service->mutable_store()->ClearProperty(kPassphraseProperty,
                                                           &error));
  EXPECT_EQ("", wifi_service->passphrase_);
}

TEST_F(WiFiServiceTest, SignalToStrength) {
  // Verify that our mapping is valid, in the sense that it preserves ordering.
  // We test that the current_map returns results as expect and fall into
  // correct category of Excellent, Good, Medium, Poor signal quality.
  for (int16_t i = std::numeric_limits<int16_t>::min();
       i < std::numeric_limits<int16_t>::max(); ++i) {
    int16_t current_mapped = WiFiService::SignalToStrength(i);
    int16_t next_mapped = WiFiService::SignalToStrength(i + 1);
    EXPECT_LE(current_mapped, next_mapped)
        << "(original values " << i << " " << i + 1 << ")";
    EXPECT_GE(current_mapped, Service::kStrengthMin);
    EXPECT_LE(current_mapped, Service::kStrengthMax);

    if (i >= -55) {
      // Excellent signal quality
      EXPECT_GE(current_mapped, 75);
      EXPECT_LE(current_mapped, Service::kStrengthMax);
    } else if (i < -55 && i >= -66) {
      // Good signal quality
      EXPECT_GE(current_mapped, 50);
      EXPECT_LE(current_mapped, 75);
    } else if (i < -66 && i >= -77) {
      // Medium signal quality
      EXPECT_GE(current_mapped, 25);
      EXPECT_LE(current_mapped, 50);
    } else if (i < -77 && i >= -88) {
      // Poor signal quality
      EXPECT_GE(current_mapped, Service::kStrengthMin);
      EXPECT_LE(current_mapped, 25);
    } else if (i < -88) {
      // No signal
      EXPECT_EQ(current_mapped, Service::kStrengthMin);
    }
  }
}

TEST_F(WiFiServiceUpdateFromEndpointsTest, Strengths) {
  // If the chosen signal values don't map to distinct strength
  // values, then we can't expect our other tests to pass. So verify
  // their distinctness.
  EXPECT_TRUE(kOkEndpointStrength != kBadEndpointStrength);
  EXPECT_TRUE(kOkEndpointStrength != kGoodEndpointStrength);
  EXPECT_TRUE(kGoodEndpointStrength != kBadEndpointStrength);
}

TEST_F(WiFiServiceUpdateFromEndpointsTest, Floating) {
  // Initial endpoint updates values.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, kOkEndpointFrequency));
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, kOkEndpointBssId));
  EXPECT_CALL(adaptor,
              EmitUint8Changed(kSignalStrengthProperty, kOkEndpointStrength));
  EXPECT_CALL(adaptor, EmitIntChanged(kWifiSignalStrengthRssiProperty,
                                      kOkEndpointSignal));
  EXPECT_CALL(adaptor,
              EmitUint16Changed(kWifiPhyMode, Metrics::kWiFiNetworkPhyMode11b));
  service->AddEndpoint(ok_endpoint);
  EXPECT_EQ(1, service->GetBSSIDConnectableEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Endpoint with stronger signal updates values.
  EXPECT_CALL(adaptor,
              EmitUint16Changed(kWifiFrequency, kGoodEndpointFrequency));
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, kGoodEndpointBssId));
  EXPECT_CALL(adaptor,
              EmitUint8Changed(kSignalStrengthProperty, kGoodEndpointStrength));
  EXPECT_CALL(adaptor, EmitIntChanged(kWifiSignalStrengthRssiProperty,
                                      kGoodEndpointSignal));
  // However, both endpoints are 11b.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiPhyMode, _)).Times(0);
  service->AddEndpoint(good_endpoint);
  EXPECT_EQ(2, service->GetBSSIDConnectableEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Endpoint with lower signal does not change values.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, _)).Times(0);
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, _)).Times(0);
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _)).Times(0);
  EXPECT_CALL(adaptor, EmitIntChanged(kWifiSignalStrengthRssiProperty, _))
      .Times(0);
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiPhyMode, _)).Times(0);
  service->AddEndpoint(bad_endpoint);
  EXPECT_EQ(3, service->GetBSSIDConnectableEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Removing non-optimal endpoint does not change values.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, _)).Times(0);
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, _)).Times(0);
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _)).Times(0);
  EXPECT_CALL(adaptor, EmitIntChanged(kWifiSignalStrengthRssiProperty, _))
      .Times(0);
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiPhyMode, _)).Times(0);
  service->RemoveEndpoint(bad_endpoint);
  EXPECT_EQ(2, service->GetBSSIDConnectableEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Removing optimal endpoint updates values.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, kOkEndpointFrequency));
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, kOkEndpointBssId));
  EXPECT_CALL(adaptor,
              EmitUint8Changed(kSignalStrengthProperty, kOkEndpointStrength));
  EXPECT_CALL(adaptor, EmitIntChanged(kWifiSignalStrengthRssiProperty,
                                      kOkEndpointSignal));
  // However, both endpoints are 11b.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiPhyMode, _)).Times(0);
  service->RemoveEndpoint(good_endpoint);
  EXPECT_EQ(1, service->GetBSSIDConnectableEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Removing last endpoint updates values (and doesn't crash).
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, _));
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, _));
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _));
  EXPECT_CALL(adaptor, EmitIntChanged(kWifiSignalStrengthRssiProperty, _));
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiPhyMode,
                                         Metrics::kWiFiNetworkPhyModeUndef));
  service->RemoveEndpoint(ok_endpoint);
  EXPECT_EQ(0, service->GetBSSIDConnectableEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);
}

TEST_F(WiFiServiceUpdateFromEndpointsTest, Connected) {
  EXPECT_CALL(adaptor, EmitUint16Changed(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitStringChanged(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitUint8Changed(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitBoolChanged(_, _)).Times(AnyNumber());
  service->AddEndpoint(bad_endpoint);
  service->AddEndpoint(ok_endpoint);
  EXPECT_EQ(2, service->GetBSSIDConnectableEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Setting current endpoint forces adoption of its values, even if it
  // doesn't have the highest signal.
  EXPECT_CALL(adaptor,
              EmitUint16Changed(kWifiFrequency, kBadEndpointFrequency));
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, kBadEndpointBssId));
  EXPECT_CALL(adaptor,
              EmitUint8Changed(kSignalStrengthProperty, kBadEndpointStrength));
  EXPECT_CALL(adaptor, EmitIntChanged(kWifiSignalStrengthRssiProperty,
                                      kBadEndpointSignal));
  service->NotifyCurrentEndpoint(bad_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);

  // Adding a better endpoint doesn't matter, when current endpoint is set.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, _)).Times(0);
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, _)).Times(0);
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _)).Times(0);
  EXPECT_CALL(adaptor, EmitIntChanged(kWifiSignalStrengthRssiProperty, _))
      .Times(0);
  service->AddEndpoint(good_endpoint);
  EXPECT_EQ(3, service->GetBSSIDConnectableEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Removing a better endpoint doesn't matter, when current endpoint is set.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, _)).Times(0);
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, _)).Times(0);
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _)).Times(0);
  EXPECT_CALL(adaptor, EmitIntChanged(kWifiSignalStrengthRssiProperty, _))
      .Times(0);
  service->RemoveEndpoint(good_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);

  // Removing the current endpoint is safe and healthy.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, kOkEndpointFrequency));
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, kOkEndpointBssId));
  EXPECT_CALL(adaptor,
              EmitUint8Changed(kSignalStrengthProperty, kOkEndpointStrength));
  EXPECT_CALL(adaptor, EmitIntChanged(kWifiSignalStrengthRssiProperty,
                                      kOkEndpointSignal));
  service->RemoveEndpoint(bad_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);

  // Clearing the current endpoint (without removing it) is also safe and
  // healthy.
  service->NotifyCurrentEndpoint(ok_endpoint);
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, _)).Times(0);
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, _)).Times(0);
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _)).Times(0);
  EXPECT_CALL(adaptor, EmitIntChanged(kWifiSignalStrengthRssiProperty, _))
      .Times(0);
  service->NotifyCurrentEndpoint(nullptr);
  Mock::VerifyAndClearExpectations(&adaptor);
}

TEST_F(WiFiServiceUpdateFromEndpointsTest, EndpointModified) {
  EXPECT_CALL(adaptor, EmitUint16Changed(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitStringChanged(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitUint8Changed(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitBoolChanged(_, _)).Times(AnyNumber());
  service->AddEndpoint(ok_endpoint);
  service->AddEndpoint(good_endpoint);
  EXPECT_EQ(2, service->GetBSSIDConnectableEndpointCount());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Updating sub-optimal Endpoint doesn't update Service.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, _)).Times(0);
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, _)).Times(0);
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _)).Times(0);
  EXPECT_CALL(adaptor, EmitIntChanged(kWifiSignalStrengthRssiProperty, _))
      .Times(0);
  ok_endpoint->signal_strength_ = (kOkEndpointSignal + kGoodEndpointSignal) / 2;
  service->NotifyEndpointUpdated(ok_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);

  // Updating optimal Endpoint updates appropriate Service property.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, _)).Times(0);
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, _)).Times(0);
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _));
  EXPECT_CALL(adaptor, EmitIntChanged(kWifiSignalStrengthRssiProperty, _));
  good_endpoint->signal_strength_ = kGoodEndpointSignal + 1;
  service->NotifyEndpointUpdated(good_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);

  // Change in optimal Endpoint updates Service properties.
  EXPECT_CALL(adaptor, EmitUint16Changed(kWifiFrequency, kOkEndpointFrequency));
  EXPECT_CALL(adaptor, EmitStringChanged(kWifiBSsid, kOkEndpointBssId));
  EXPECT_CALL(adaptor, EmitUint8Changed(kSignalStrengthProperty, _));
  EXPECT_CALL(adaptor, EmitIntChanged(kWifiSignalStrengthRssiProperty, _));
  ok_endpoint->signal_strength_ = kGoodEndpointSignal + 2;
  service->NotifyEndpointUpdated(ok_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);
}

TEST_F(WiFiServiceUpdateFromEndpointsTest, PhysicalMode) {
  EXPECT_CALL(adaptor, EmitUint16Changed(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitStringChanged(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitUint8Changed(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitBoolChanged(_, _)).Times(AnyNumber());

  // No endpoints -> undef.
  EXPECT_EQ(Metrics::kWiFiNetworkPhyModeUndef, service->ap_physical_mode());

  // Endpoint has unknown physical mode -> undef.
  ok_endpoint->physical_mode_ = Metrics::kWiFiNetworkPhyModeUndef;
  service->AddEndpoint(ok_endpoint);
  EXPECT_EQ(Metrics::kWiFiNetworkPhyModeUndef, service->ap_physical_mode());

  // New endpoint with 802.11a -> 802.11a.
  good_endpoint->physical_mode_ = Metrics::kWiFiNetworkPhyMode11a;
  service->AddEndpoint(good_endpoint);
  EXPECT_EQ(Metrics::kWiFiNetworkPhyMode11a, service->ap_physical_mode());

  // Remove 802.11a endpoint -> undef.
  service->RemoveEndpoint(good_endpoint);
  EXPECT_EQ(Metrics::kWiFiNetworkPhyModeUndef, service->ap_physical_mode());

  // Change endpoint -> take endpoint's new value.
  ok_endpoint->physical_mode_ = Metrics::kWiFiNetworkPhyMode11n;
  service->NotifyEndpointUpdated(ok_endpoint);
  EXPECT_EQ(Metrics::kWiFiNetworkPhyMode11n, service->ap_physical_mode());

  // No endpoints -> undef.
  service->RemoveEndpoint(ok_endpoint);
  EXPECT_EQ(Metrics::kWiFiNetworkPhyModeUndef, service->ap_physical_mode());
}

TEST_F(WiFiServiceUpdateFromEndpointsTest, WarningOnDisconnect) {
  service->AddEndpoint(ok_endpoint);
  service->SetState(Service::kStateAssociating);
  ScopedMockLog log;
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(log, Log(logging::LOGGING_WARNING, _,
                       EndsWith("disconnect due to no remaining endpoints.")));
  service->RemoveEndpoint(ok_endpoint);
}

MATCHER_P(IsSetwiseEqual, expected_set, "") {
  std::set<uint16_t> arg_set(arg.begin(), arg.end());
  return arg_set == expected_set;
}

TEST_F(WiFiServiceUpdateFromEndpointsTest, FrequencyList) {
  EXPECT_CALL(adaptor, EmitUint16Changed(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitStringChanged(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitUint8Changed(_, _)).Times(AnyNumber());
  EXPECT_CALL(adaptor, EmitBoolChanged(_, _)).Times(AnyNumber());

  // No endpoints -> empty list.
  EXPECT_EQ(std::vector<uint16_t>(), service->frequency_list());

  // Add endpoint -> endpoint's frequency in list.
  EXPECT_CALL(adaptor, EmitUint16sChanged(
                           kWifiFrequencyListProperty,
                           std::vector<uint16_t>{kGoodEndpointFrequency}));
  service->AddEndpoint(good_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);

  // Add another endpoint -> both frequencies in list.
  // Order doesn't matter.
  std::set<uint16_t> expected_frequencies{kGoodEndpointFrequency,
                                          kOkEndpointFrequency};
  EXPECT_CALL(adaptor,
              EmitUint16sChanged(kWifiFrequencyListProperty,
                                 IsSetwiseEqual(expected_frequencies)));
  service->AddEndpoint(ok_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);

  // Remove endpoint -> other endpoint's frequency remains.
  EXPECT_CALL(adaptor,
              EmitUint16sChanged(kWifiFrequencyListProperty,
                                 std::vector<uint16_t>{kOkEndpointFrequency}));
  service->RemoveEndpoint(good_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);

  // Endpoint with same frequency -> frequency remains.
  // Notification may or may not occur -- don't care.
  // Frequency may or may not be repeated in list -- don't care.
  WiFiEndpointRefPtr same_freq_as_ok_endpoint = MakeOpenEndpoint(
      simple_ssid_string(), "aa:bb:cc:dd:ee:ff", ok_endpoint->frequency(), 0);
  service->AddEndpoint(same_freq_as_ok_endpoint);
  EXPECT_THAT(service->frequency_list(),
              IsSetwiseEqual(std::set<uint16_t>{kOkEndpointFrequency}));
  Mock::VerifyAndClearExpectations(&adaptor);

  // Remove endpoint with same frequency -> frequency remains.
  // Notification may or may not occur -- don't care.
  service->RemoveEndpoint(ok_endpoint);
  EXPECT_EQ(std::vector<uint16_t>{same_freq_as_ok_endpoint->frequency()},
            service->frequency_list());
  Mock::VerifyAndClearExpectations(&adaptor);

  // Remove last endpoint. Frequency list goes empty.
  EXPECT_CALL(adaptor, EmitUint16sChanged(kWifiFrequencyListProperty,
                                          std::vector<uint16_t>{}));
  service->RemoveEndpoint(same_freq_as_ok_endpoint);
  Mock::VerifyAndClearExpectations(&adaptor);
}

TEST_F(WiFiServiceTest, ComputeSecurityClass) {
  EXPECT_EQ(WiFiService::ComputeSecurityClass(WiFiSecurity::kNone),
            kSecurityClassNone);
  EXPECT_EQ(WiFiService::ComputeSecurityClass(WiFiSecurity::kWep),
            kSecurityClassWep);
  for (auto mode :
       {WiFiSecurity::kWpa, WiFiSecurity::kWpaWpa2, WiFiSecurity::kWpaAll,
        WiFiSecurity::kWpa2, WiFiSecurity::kWpa2Wpa3, WiFiSecurity::kWpa3}) {
    EXPECT_EQ(WiFiService::ComputeSecurityClass(mode), kSecurityClassPsk);
  }
  for (auto mode :
       {WiFiSecurity::kWpaEnterprise, WiFiSecurity::kWpaWpa2Enterprise,
        WiFiSecurity::kWpaAllEnterprise, WiFiSecurity::kWpa2Enterprise,
        WiFiSecurity::kWpa2Wpa3Enterprise, WiFiSecurity::kWpa3Enterprise}) {
    EXPECT_EQ(WiFiService::ComputeSecurityClass(mode), kSecurityClass8021x);
  }
}

TEST_F(WiFiServiceTest, Is8021x) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);
  EXPECT_FALSE(service->Is8021x());
  service = MakeSimpleService(kSecurityClassWep);
  EXPECT_FALSE(service->Is8021x());
  service = MakeSimpleService(kSecurityClassPsk);
  for (auto mode :
       {WiFiSecurity::kWpa, WiFiSecurity::kWpaWpa2, WiFiSecurity::kWpaAll,
        WiFiSecurity::kWpa2, WiFiSecurity::kWpa2Wpa3, WiFiSecurity::kWpa3}) {
    service->security_ = mode;
    EXPECT_FALSE(service->Is8021x());
  }
  service = MakeSimpleService(kSecurityClass8021x);
  for (auto mode :
       {WiFiSecurity::kWpaEnterprise, WiFiSecurity::kWpaWpa2Enterprise,
        WiFiSecurity::kWpaAllEnterprise, WiFiSecurity::kWpa2Enterprise,
        WiFiSecurity::kWpa2Wpa3Enterprise, WiFiSecurity::kWpa3Enterprise}) {
    service->security_ = mode;
    EXPECT_TRUE(service->Is8021x());
  }
}

TEST_F(WiFiServiceTest, UpdateSecurity) {
  // Cleartext and pre-shared-key crypto.
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);
    EXPECT_EQ(Service::kCryptoNone, service->crypto_algorithm());
    EXPECT_FALSE(service->key_rotation());
    EXPECT_FALSE(service->endpoint_auth());
  }
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassWep);
    EXPECT_EQ(Service::kCryptoRc4, service->crypto_algorithm());
    EXPECT_FALSE(service->key_rotation());
    EXPECT_FALSE(service->endpoint_auth());
  }
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassPsk);
    EXPECT_EQ(Service::kCryptoRc4, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_FALSE(service->endpoint_auth());
  }
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassPsk);
    WiFiEndpoint::SecurityFlags flags;
    flags.wpa_psk = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    EXPECT_EQ(WiFiSecurity::kWpa, service->security());
    EXPECT_EQ(Service::kCryptoRc4, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_FALSE(service->endpoint_auth());
  }
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassPsk);
    WiFiEndpoint::SecurityFlags flags;
    flags.wpa_psk = true;
    WiFiEndpointRefPtr endpoint1 =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint1);
    flags.rsn_psk = true;
    WiFiEndpointRefPtr endpoint2 =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint2);
    EXPECT_EQ(WiFiSecurity::kWpaWpa2, service->security());
    // Service in WPA/WPA2 mixed mode with a pure WPA endpoint should stick to
    // RC4 algorithm.
    EXPECT_EQ(Service::kCryptoRc4, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_FALSE(service->endpoint_auth());
  }
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassPsk);
    WiFiEndpoint::SecurityFlags flags;
    flags.rsn_psk = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    EXPECT_EQ(WiFiSecurity::kWpa2, service->security());
    // Downgrade to mixed mode.
    service->security_ = WiFiSecurity::kWpaWpa2;
    // Service in WPA/WPA2 mixed mode but without any pure WPA endpoint should
    // switch to AES algorithm.
    EXPECT_EQ(Service::kCryptoAes, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_FALSE(service->endpoint_auth());
  }
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassPsk);
    WiFiEndpoint::SecurityFlags flags;
    flags.rsn_psk = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    EXPECT_EQ(WiFiSecurity::kWpa2, service->security());
    EXPECT_EQ(Service::kCryptoAes, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_FALSE(service->endpoint_auth());
  }
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassPsk);
    WiFiEndpoint::SecurityFlags flags;
    flags.rsn_psk = true;
    flags.rsn_sae = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    EXPECT_EQ(WiFiSecurity::kWpa2Wpa3, service->security());
    EXPECT_EQ(Service::kCryptoAes, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_FALSE(service->endpoint_auth());
  }
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassPsk);
    WiFiEndpoint::SecurityFlags flags;
    flags.rsn_sae = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    EXPECT_EQ(WiFiSecurity::kWpa3, service->security());
    EXPECT_EQ(Service::kCryptoAes, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_FALSE(service->endpoint_auth());
  }

  // Crypto with 802.1X key management.
  {
    // WEP
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassWep);
    service->SetEAPKeyManagement("IEEE8021X");
    EXPECT_EQ(Service::kCryptoRc4, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_TRUE(service->endpoint_auth());
  }
  {
    // WPA
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityClass8021x);
    WiFiEndpoint::SecurityFlags flags;
    flags.wpa_8021x = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    EXPECT_EQ(Service::kCryptoRc4, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_TRUE(service->endpoint_auth());
  }
  {
    // RSN
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityClass8021x);
    WiFiEndpoint::SecurityFlags flags;
    flags.rsn_8021x = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    EXPECT_EQ(Service::kCryptoAes, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_TRUE(service->endpoint_auth());
  }
  {
    // AP supports both WPA and RSN.
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityClass8021x);
    WiFiEndpoint::SecurityFlags flags;
    flags.wpa_8021x = true;
    flags.rsn_8021x = true;
    WiFiEndpointRefPtr endpoint =
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(endpoint);
    EXPECT_EQ(Service::kCryptoAes, service->crypto_algorithm());
    EXPECT_TRUE(service->key_rotation());
    EXPECT_TRUE(service->endpoint_auth());
  }
}

TEST_F(WiFiServiceTest, ComputeCipher8021x) {
  WiFiEndpoint::SecurityFlags open_flags;
  WiFiEndpoint::SecurityFlags wpa_flags;
  wpa_flags.wpa_psk = true;
  WiFiEndpoint::SecurityFlags rsn_flags;
  rsn_flags.rsn_psk = true;
  WiFiEndpoint::SecurityFlags wparsn_flags;
  wparsn_flags.wpa_psk = true;
  wparsn_flags.rsn_psk = true;

  // No endpoints.
  {
    const std::set<WiFiEndpointConstRefPtr> endpoints;
    EXPECT_EQ(Service::kCryptoNone, WiFiService::ComputeCipher8021x(endpoints));
  }

  // Single endpoint, various configs.
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, open_flags));
    EXPECT_EQ(Service::kCryptoNone, WiFiService::ComputeCipher8021x(endpoints));
  }
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, wpa_flags));
    EXPECT_EQ(Service::kCryptoRc4, WiFiService::ComputeCipher8021x(endpoints));
  }
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, rsn_flags));
    EXPECT_EQ(Service::kCryptoAes, WiFiService::ComputeCipher8021x(endpoints));
  }
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, wparsn_flags));
    EXPECT_EQ(Service::kCryptoAes, WiFiService::ComputeCipher8021x(endpoints));
  }

  // Multiple endpoints.
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, open_flags));
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:02", 0, 0, open_flags));
    EXPECT_EQ(Service::kCryptoNone, WiFiService::ComputeCipher8021x(endpoints));
  }
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, open_flags));
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:02", 0, 0, wpa_flags));
    EXPECT_EQ(Service::kCryptoNone, WiFiService::ComputeCipher8021x(endpoints));
  }
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, wpa_flags));
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:02", 0, 0, wpa_flags));
    EXPECT_EQ(Service::kCryptoRc4, WiFiService::ComputeCipher8021x(endpoints));
  }
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, wpa_flags));
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:02", 0, 0, rsn_flags));
    EXPECT_EQ(Service::kCryptoRc4, WiFiService::ComputeCipher8021x(endpoints));
  }
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, rsn_flags));
    endpoints.insert(MakeEndpoint("a", "00:00:00:00:00:02", 0, 0, rsn_flags));
    EXPECT_EQ(Service::kCryptoAes, WiFiService::ComputeCipher8021x(endpoints));
  }
  {
    std::set<WiFiEndpointConstRefPtr> endpoints;
    endpoints.insert(
        MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, wparsn_flags));
    endpoints.insert(
        MakeEndpoint("a", "00:00:00:00:00:02", 0, 0, wparsn_flags));
    EXPECT_EQ(Service::kCryptoAes, WiFiService::ComputeCipher8021x(endpoints));
  }
}

TEST_F(WiFiServiceTest, Unload) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  auto network = std::make_unique<MockNetwork>(1, "ifname", Technology::kWiFi);
  EXPECT_CALL(*network, DestroyDHCPLease(service->GetStorageIdentifier()))
      .Times(1);
  wifi()->set_network_for_testing(std::move(network));
  service->Unload();
}

TEST_F(WiFiServiceTest, PropertyChanges) {
  WiFiServiceRefPtr service = MakeServiceWithMockManager();
  ServiceMockAdaptor* adaptor = GetAdaptor(service.get());
  // It is important to test these property changes before having wifi pointer
  // set because there are race scenarios where e.g. due to event queueing we
  // could end up transitioning to connected without having valid wifi device,
  // so shill needs to be ready for this.
  TestCommonPropertyChanges(service, adaptor);
  TestAutoConnectPropertyChange(service, adaptor);

  EXPECT_CALL(*adaptor, EmitRpcIdentifierChanged(kDeviceProperty, _));
  SetWiFi(service, wifi());
  Mock::VerifyAndClearExpectations(adaptor);

  EXPECT_CALL(*adaptor, EmitRpcIdentifierChanged(kDeviceProperty, _));
  service->ResetWiFi();
  Mock::VerifyAndClearExpectations(adaptor);
}

// Custom property setters should return false, and make no changes, if
// the new value is the same as the old value.
TEST_F(WiFiServiceTest, CustomSetterNoopChange) {
  WiFiServiceRefPtr service = MakeServiceWithMockManager();
  TestCustomSetterNoopChange(service, mock_manager());
}

TEST_F(WiFiServiceTest, SuspectedCredentialFailure) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassPsk);
  EXPECT_FALSE(service->has_ever_connected());
  EXPECT_EQ(0, service->suspected_credential_failures_);

  EXPECT_TRUE(service->AddAndCheckSuspectedCredentialFailure());
  EXPECT_EQ(1, service->suspected_credential_failures_);

  // Reset failure state upon successful connection.
  service->ResetSuspectedCredentialFailures();
  service->SetState(Service::kStateConnected);
  for (int i = 0; i < WiFiService::kSuspectedCredentialFailureThreshold - 1;
       ++i) {
    EXPECT_FALSE(service->AddAndCheckSuspectedCredentialFailure());
    EXPECT_EQ(i + 1, service->suspected_credential_failures_);
  }
  EXPECT_TRUE(service->AddAndCheckSuspectedCredentialFailure());
  // Make sure the failure state does not reset just because we ask again.
  EXPECT_TRUE(service->AddAndCheckSuspectedCredentialFailure());

  // Make sure the failure state resets because of a credential change.
  // A credential change changes the has_ever_connected to false and
  // immediately returns true when attempting to add the failure.
  Error error;
  service->SetPassphrase("Panchromatic Resonance", &error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(0, service->suspected_credential_failures_);
  EXPECT_TRUE(service->AddAndCheckSuspectedCredentialFailure());
  service->ResetSuspectedCredentialFailures();
  EXPECT_EQ(0, service->suspected_credential_failures_);

  // Make sure that we still return true after resetting the failure
  // count.
  service->suspected_credential_failures_ = 3;
  EXPECT_EQ(3, service->suspected_credential_failures_);
  service->ResetSuspectedCredentialFailures();
  EXPECT_EQ(0, service->suspected_credential_failures_);
  EXPECT_TRUE(service->AddAndCheckSuspectedCredentialFailure());
}

TEST_F(WiFiServiceTest, GetTethering) {
  MockNetwork network(1, "ifname", Technology::kWiFi);
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);
  service->SetAttachedNetwork(network.AsWeakPtr());
  EXPECT_EQ(Service::TetheringState::kNotDetected, service->GetTethering());

  // Since the device isn't connected, we shouldn't even query the WiFi device.
  EXPECT_CALL(network, IsConnectedViaTether()).Times(0);
  SetWiFiForService(service, wifi());
  EXPECT_EQ(Service::TetheringState::kNotDetected, service->GetTethering());
  Mock::VerifyAndClearExpectations(wifi().get());

  scoped_refptr<MockProfile> mock_profile(new NiceMock<MockProfile>(manager()));
  service->set_profile(mock_profile);
  service->SetState(Service::kStateConnected);

  // A connected service should return "confirmed" iff the underlying device
  // reports it is tethered.
  EXPECT_CALL(network, IsConnectedViaTether())
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  EXPECT_EQ(Service::TetheringState::kConfirmed, service->GetTethering());
  EXPECT_EQ(Service::TetheringState::kNotDetected, service->GetTethering());
  Mock::VerifyAndClearExpectations(wifi().get());

  // Add two endpoints that have a BSSID associated with some Android devices
  // in tethering mode.
  WiFiEndpointRefPtr endpoint_android1 =
      MakeOpenEndpoint("a", "02:1a:11:00:00:01", 2412, 0);
  service->AddEndpoint(endpoint_android1);
  WiFiEndpointRefPtr endpoint_android2 =
      MakeOpenEndpoint("a", "02:1a:11:00:00:02", 2412, 0);
  service->AddEndpoint(endpoint_android2);

  // Since there are two endpoints, we should not detect tethering mode.
  EXPECT_CALL(network, IsConnectedViaTether()).WillOnce(Return(false));
  EXPECT_EQ(Service::TetheringState::kNotDetected, service->GetTethering());

  // If the device reports that it is tethered, this should override any
  // findings gained from examining the endpoints.
  EXPECT_CALL(network, IsConnectedViaTether()).WillOnce(Return(true));
  EXPECT_EQ(Service::TetheringState::kConfirmed, service->GetTethering());

  // Continue in the un-tethered device case for a few more tests below.
  Mock::VerifyAndClearExpectations(wifi().get());
  EXPECT_CALL(network, IsConnectedViaTether()).WillRepeatedly(Return(false));

  // Removing an endpoint so we only have one should put us in the "Suspected"
  // state.
  service->RemoveEndpoint(endpoint_android1);
  EXPECT_EQ(Service::TetheringState::kSuspected, service->GetTethering());

  // Add a different endpoint which has a locally administered MAC address
  // but not one used by Android.
  service->RemoveEndpoint(endpoint_android2);
  WiFiEndpointRefPtr endpoint_ios =
      MakeOpenEndpoint("a", "02:00:00:00:00:01", 2412, 0);
  service->AddEndpoint(endpoint_ios);
  EXPECT_EQ(Service::TetheringState::kNotDetected, service->GetTethering());

  // If this endpoint reports the right vendor OUI, we should suspect
  // it to be tethered.  However since this evaluation normally only
  // happens in the endpoint constructor, we must force it to recalculate.
  endpoint_ios->vendor_information_.oui_set.insert(Tethering::kIosOui);
  endpoint_ios->CheckForTetheringSignature();
  EXPECT_EQ(Service::TetheringState::kSuspected, service->GetTethering());

  // If the device reports that it is tethered, this should override any
  // findings gained from examining the endpoints.
  Mock::VerifyAndClearExpectations(wifi().get());
  EXPECT_CALL(network, IsConnectedViaTether()).WillOnce(Return(true));
  EXPECT_EQ(Service::TetheringState::kConfirmed, service->GetTethering());
}

TEST_F(WiFiServiceTest, IsVisible) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityClassNone);
  ServiceMockAdaptor* adaptor = GetAdaptor(wifi_service.get());

  // Adding the first endpoint emits a change: Visible = true.
  EXPECT_CALL(*adaptor, EmitBoolChanged(kVisibleProperty, true));
  WiFiEndpointRefPtr endpoint =
      MakeOpenEndpoint("a", "00:00:00:00:00:01", 0, 0);
  wifi_service->AddEndpoint(endpoint);
  EXPECT_TRUE(wifi_service->IsVisible());
  Mock::VerifyAndClearExpectations(adaptor);

  // Removing the last endpoint emits a change: Visible = false.
  EXPECT_CALL(*adaptor, EmitBoolChanged(kVisibleProperty, false));
  wifi_service->RemoveEndpoint(endpoint);
  EXPECT_FALSE(wifi_service->IsVisible());
  Mock::VerifyAndClearExpectations(adaptor);

  // Entering the a connecting state emits a change: Visible = true
  // although the service has no endpoints.
  EXPECT_CALL(*adaptor, EmitBoolChanged(kVisibleProperty, true));
  wifi_service->SetState(Service::kStateAssociating);
  EXPECT_TRUE(wifi_service->IsVisible());
  Mock::VerifyAndClearExpectations(adaptor);

  // Moving between connecting / connected states does not trigger an Emit.
  EXPECT_CALL(*adaptor, EmitBoolChanged(kVisibleProperty, _)).Times(0);
  wifi_service->SetState(Service::kStateConfiguring);
  EXPECT_TRUE(wifi_service->IsVisible());
  Mock::VerifyAndClearExpectations(adaptor);

  // Entering the Idle state emits a change: Visible = false.
  EXPECT_CALL(*adaptor, EmitBoolChanged(kVisibleProperty, false));
  wifi_service->SetState(Service::kStateIdle);
  EXPECT_FALSE(wifi_service->IsVisible());
  Mock::VerifyAndClearExpectations(adaptor);
}

TEST_F(WiFiServiceTest, ChooseDevice) {
  scoped_refptr<MockWiFi> wifi = MakeSimpleWiFi("test_wifi");
  WiFiServiceRefPtr service = MakeServiceWithMockManager();

  EXPECT_CALL(*mock_manager(),
              GetEnabledDeviceWithTechnology(Technology(Technology::kWiFi)))
      .WillOnce(Return(wifi));
  EXPECT_EQ(wifi, service->ChooseDevice());
  Mock::VerifyAndClearExpectations(mock_manager());
}

TEST_F(WiFiServiceTest, SetMACPolicy) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityClassNone);
  Error ret;

  EXPECT_FALSE(wifi_service->SetMACPolicy("foo", &ret));
  EXPECT_FALSE(ret.IsSuccess());
  EXPECT_FALSE(wifi_service->SetMACPolicy("", &ret));
  EXPECT_FALSE(ret.IsSuccess());

  wifi()->random_mac_supported_ = true;
  EXPECT_TRUE(wifi_service->SetMACPolicy(kWifiRandomMacPolicyHardware, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::Hardware);
  EXPECT_TRUE(wifi_service->SetMACPolicy(kWifiRandomMacPolicyFullRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::FullRandom);
  EXPECT_TRUE(wifi_service->SetMACPolicy(kWifiRandomMacPolicyOUIRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::OUIRandom);
  EXPECT_TRUE(
      wifi_service->SetMACPolicy(kWifiRandomMacPolicyPersistentRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::PersistentRandom);
  EXPECT_TRUE(wifi_service->SetMACPolicy(
      kWifiRandomMacPolicyNonPersistentRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::NonPersistentRandom);

  wifi()->random_mac_supported_ = false;
  EXPECT_TRUE(wifi_service->SetMACPolicy(kWifiRandomMacPolicyHardware, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::Hardware);
  EXPECT_FALSE(
      wifi_service->SetMACPolicy(kWifiRandomMacPolicyFullRandom, &ret));
  EXPECT_FALSE(ret.IsSuccess());
  EXPECT_FALSE(wifi_service->SetMACPolicy(kWifiRandomMacPolicyOUIRandom, &ret));
  EXPECT_FALSE(ret.IsSuccess());
  EXPECT_FALSE(
      wifi_service->SetMACPolicy(kWifiRandomMacPolicyPersistentRandom, &ret));
  EXPECT_FALSE(ret.IsSuccess());
  EXPECT_FALSE(wifi_service->SetMACPolicy(
      kWifiRandomMacPolicyNonPersistentRandom, &ret));
  EXPECT_FALSE(ret.IsSuccess());
}

bool verifyAddressCorrect(const MACAddress& addr) {
  static constexpr auto kMulticastBit = 1 << 0;
  static constexpr auto kLocallyAdministeredBit = 1 << 1;
  EXPECT_TRUE(addr.is_set());
  uint8_t msb;
  EXPECT_EQ(sscanf(addr.ToString().substr(0, 2).c_str(), "%02hhx", &msb), 1);
  EXPECT_EQ((msb & (kMulticastBit | kLocallyAdministeredBit)),
            kLocallyAdministeredBit);
  return addr.is_set() && ((msb & (kMulticastBit | kLocallyAdministeredBit)) ==
                           kLocallyAdministeredBit);
}

TEST_F(WiFiServiceTest, UpdateMACAddressNonPersistentPolicy) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityClassNone);
  wifi()->random_mac_supported_ = true;
  auto clock_ptr = std::make_unique<base::SimpleTestClock>();
  base::SimpleTestClock* clock = clock_ptr.get();
  wifi_service->clock_ = std::move(clock_ptr);
  Error ret;

  EXPECT_TRUE(wifi_service->SetMACPolicy(
      kWifiRandomMacPolicyNonPersistentRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::NonPersistentRandom);
  auto mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  // We have switched from default Hardware policy so this should be qualified
  // as a "policy related update".
  EXPECT_TRUE(mac.policy_change);
  EXPECT_TRUE(verifyAddressCorrect(wifi_service->mac_address_));
  auto addr = wifi_service->mac_address_.ToString();
  clock->Advance(MACAddress::kDefaultExpirationTime);
  // Set these times to first test MAC expiry path
  wifi_service->disconnect_time_ = clock->Now();
  wifi_service->dhcp4_lease_expiry_ = clock->Now() + base::Hours(1);
  mac = wifi_service->UpdateMACAddress();
  EXPECT_TRUE(mac.mac.empty());
  EXPECT_FALSE(mac.policy_change);
  EXPECT_EQ(wifi_service->mac_address_.ToString(), addr);

  // Make sure local admin bit is cleared.
  addr[1] = 'd';
  wifi_service->mac_address_.Set(addr);
  // Cross the MAC expiry
  clock->Advance(base::Seconds(1));
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_FALSE(mac.policy_change);
  EXPECT_TRUE(verifyAddressCorrect(wifi_service->mac_address_));
  EXPECT_NE(wifi_service->mac_address_.ToString(), addr);

  addr = wifi_service->mac_address_.ToString();
  // MAC is valid for 24h now so next rotation time is disconnect + 4h.
  // Let's test some point from (disconnect, lease_expiry) period.
  clock->Advance(base::Minutes(30));
  mac = wifi_service->UpdateMACAddress();
  EXPECT_TRUE(mac.mac.empty());
  EXPECT_FALSE(mac.policy_change);
  EXPECT_EQ(wifi_service->mac_address_.ToString(), addr);
  // Now [lease_expiry, disconnect + 4h) period - should still be no
  // change.
  clock->Advance(base::Hours(2));
  mac = wifi_service->UpdateMACAddress();
  EXPECT_TRUE(mac.mac.empty());
  EXPECT_FALSE(mac.policy_change);
  EXPECT_EQ(wifi_service->mac_address_.ToString(), addr);
  // Now cross the rotation deadline - address should change.
  addr[1] = 'd';
  wifi_service->mac_address_.Set(addr);
  clock->Advance(base::Hours(2));
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_FALSE(mac.policy_change);
  EXPECT_NE(wifi_service->mac_address_.ToString(), addr);
}

TEST_F(WiFiServiceTest, UpdateMACAddressPersistentPolicy) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityClassNone);
  wifi()->random_mac_supported_ = true;
  auto clock_ptr = std::make_unique<base::SimpleTestClock>();
  base::SimpleTestClock* clock = clock_ptr.get();
  wifi_service->clock_ = std::move(clock_ptr);
  wifi_service->security_ = WiFiSecurity::kWpaWpa2;
  wifi_service->was_portal_detected_ = 1;
  Error ret;

  EXPECT_TRUE(
      wifi_service->SetMACPolicy(kWifiRandomMacPolicyPersistentRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::PersistentRandom);

  auto mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  // We have switched from default Hardware policy so this should be qualified
  // as a "policy related update".
  EXPECT_TRUE(mac.policy_change);
  EXPECT_TRUE(verifyAddressCorrect(wifi_service->mac_address_));
  auto addr = wifi_service->mac_address_.ToString();
  // Check if lease/disconnect time does not cause rotation
  wifi_service->disconnect_time_ = clock->Now() - base::Hours(5);
  wifi_service->dhcp4_lease_expiry_ = clock->Now() - base::Hours(1);
  mac = wifi_service->UpdateMACAddress();
  EXPECT_TRUE(mac.mac.empty());
  EXPECT_FALSE(mac.policy_change);
  EXPECT_EQ(wifi_service->mac_address_.ToString(), addr);

  clock->Advance(MACAddress::kDefaultExpirationTime + base::Seconds(1));
  mac = wifi_service->UpdateMACAddress();
  EXPECT_TRUE(mac.mac.empty());
  EXPECT_FALSE(mac.policy_change);
  EXPECT_EQ(wifi_service->mac_address_.ToString(), addr);
  wifi_service->security_ = WiFiSecurity::kNone;
  clock->Advance(MACAddress::kDefaultExpirationTime + base::Seconds(1));
  mac = wifi_service->UpdateMACAddress();
  EXPECT_TRUE(mac.mac.empty());
  EXPECT_FALSE(mac.policy_change);
  EXPECT_EQ(wifi_service->mac_address_.ToString(), addr);
  wifi_service->was_portal_detected_ = 0;

  wifi_service->mac_address_.Clear();
  clock->Advance(MACAddress::kDefaultExpirationTime + base::Seconds(1));
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_FALSE(mac.policy_change);
  addr = wifi_service->mac_address_.ToString();
  // Make sure local admin bit is cleared.
  addr[1] = 'd';
  wifi_service->mac_address_.Set(addr);
  clock->Advance(MACAddress::kDefaultExpirationTime + base::Seconds(1));
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_FALSE(mac.policy_change);
  EXPECT_TRUE(verifyAddressCorrect(wifi_service->mac_address_));
  EXPECT_NE(wifi_service->mac_address_.ToString(), addr);
}

TEST_F(WiFiServiceTest, UpdateMACAddressPolicySwitch) {
  WiFiServiceRefPtr wifi_service = MakeServiceWithWiFi(kSecurityClassNone);
  wifi()->random_mac_supported_ = true;
  wifi_service->security_ = WiFiSecurity::kWpaWpa2;
  wifi_service->was_portal_detected_ = 1;
  Error ret;

  EXPECT_TRUE(
      wifi_service->SetMACPolicy(kWifiRandomMacPolicyPersistentRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::PersistentRandom);
  auto mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(wifi_service->mac_address_.will_expire());
  auto addr = wifi_service->mac_address_.ToString();
  // Make sure local admin bit is cleared.
  addr[1] = 'd';
  wifi_service->mac_address_.Set(addr);
  // Simulate changing policy.
  EXPECT_TRUE(wifi_service->SetMACPolicy(
      kWifiRandomMacPolicyNonPersistentRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::NonPersistentRandom);
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  // We have switched from PersistentRandom policy so this should be qualified
  // as a "policy related update".
  EXPECT_TRUE(mac.policy_change);
  EXPECT_NE(wifi_service->mac_address_.ToString(), addr);
  EXPECT_TRUE(verifyAddressCorrect(wifi_service->mac_address_));
  EXPECT_TRUE(wifi_service->mac_address_.will_expire());

  addr = wifi_service->mac_address_.ToString();
  addr[1] = 'd';
  wifi_service->mac_address_.Set(addr);
  EXPECT_TRUE(
      wifi_service->SetMACPolicy(kWifiRandomMacPolicyPersistentRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::PersistentRandom);
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_TRUE(mac.policy_change);
  EXPECT_NE(wifi_service->mac_address_.ToString(), addr);
  EXPECT_FALSE(wifi_service->mac_address_.will_expire());

  addr = wifi_service->mac_address_.ToString();
  addr[1] = 'd';
  wifi_service->mac_address_.Set(addr);
  EXPECT_TRUE(wifi_service->SetMACPolicy(
      kWifiRandomMacPolicyNonPersistentRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::NonPersistentRandom);
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_TRUE(mac.policy_change);
  EXPECT_NE(wifi_service->mac_address_.ToString(), addr);
  EXPECT_TRUE(verifyAddressCorrect(wifi_service->mac_address_));
  EXPECT_TRUE(wifi_service->mac_address_.will_expire());

  // When switching back to Hardware policy or to random policies where MAC
  // rotation is handled by the WPA supplicant our random MAC does not change,
  // but we do not test this leaving this as implementation defined behaviour.
  // Important is that after going to policies that are handled by shill the MAC
  // address should rotate - and this is what we test at the end.
  EXPECT_TRUE(wifi_service->SetMACPolicy(kWifiRandomMacPolicyHardware, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::Hardware);
  mac = wifi_service->UpdateMACAddress();
  EXPECT_TRUE(mac.mac.empty());
  EXPECT_TRUE(mac.policy_change);

  EXPECT_TRUE(wifi_service->SetMACPolicy(kWifiRandomMacPolicyFullRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::FullRandom);
  mac = wifi_service->UpdateMACAddress();
  EXPECT_TRUE(mac.mac.empty());
  EXPECT_TRUE(mac.policy_change);

  // We don't change policy but with FullRandom call UpdateMACAddress() again
  // - which simumlates attempt of another connection (this function is only
  // called in WiFi::ConnectTo()).  This should indicate no change.  In reality
  // there might be a change but it will be detected upon the change itself not
  // upfront during connection.
  EXPECT_TRUE(wifi_service->SetMACPolicy(kWifiRandomMacPolicyFullRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::FullRandom);
  mac = wifi_service->UpdateMACAddress();
  EXPECT_TRUE(mac.mac.empty());
  EXPECT_FALSE(mac.policy_change);

  EXPECT_TRUE(wifi_service->SetMACPolicy(kWifiRandomMacPolicyOUIRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::OUIRandom);
  mac = wifi_service->UpdateMACAddress();
  EXPECT_TRUE(mac.mac.empty());
  EXPECT_TRUE(mac.policy_change);

  // The same case as for FullRandom above - subsequent connection (which would
  // result in call to UpdateMACAddress()) without policy changed can result in
  // "external" mac change, however we have nothing to configure and
  // UpdateMACAddress() should return "no change".
  EXPECT_TRUE(wifi_service->SetMACPolicy(kWifiRandomMacPolicyOUIRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::OUIRandom);
  mac = wifi_service->UpdateMACAddress();
  EXPECT_TRUE(mac.mac.empty());
  EXPECT_FALSE(mac.policy_change);

  addr = wifi_service->mac_address_.ToString();
  addr[1] = 'd';
  wifi_service->mac_address_.Set(addr);
  EXPECT_TRUE(
      wifi_service->SetMACPolicy(kWifiRandomMacPolicyPersistentRandom, &ret));
  EXPECT_EQ(wifi_service->random_mac_policy_,
            WiFiService::RandomizationPolicy::PersistentRandom);
  mac = wifi_service->UpdateMACAddress();
  EXPECT_FALSE(mac.mac.empty());
  EXPECT_TRUE(mac.policy_change);
  EXPECT_NE(wifi_service->mac_address_.ToString(), addr);
  EXPECT_FALSE(wifi_service->mac_address_.will_expire());
}

TEST_F(WiFiServiceTest, RandomizationNotSupported) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  wifi()->random_mac_supported_ = false;
  Error ret;

  EXPECT_TRUE(service->SetMACPolicy(kWifiRandomMacPolicyHardware, &ret));
  EXPECT_FALSE(service->SetMACPolicy(kWifiRandomMacPolicyFullRandom, &ret));
  EXPECT_FALSE(service->SetMACPolicy(kWifiRandomMacPolicyOUIRandom, &ret));
  EXPECT_FALSE(
      service->SetMACPolicy(kWifiRandomMacPolicyPersistentRandom, &ret));
  EXPECT_FALSE(
      service->SetMACPolicy(kWifiRandomMacPolicyNonPersistentRandom, &ret));
}

TEST_F(WiFiServiceTest, RandomizationBlocklist) {
  std::array<std::string, 5> ssid_blocklist = {
      "ACWiFi", "AA-Inflight", "gogoinflight", "DeltaWiFi", "DeltaWiFi.com"};

  for (auto& ssid : ssid_blocklist) {
    auto service = MakeServiceSSID(kSecurityClassPsk, ssid);
    Error ret;
    EXPECT_TRUE(service->SetMACPolicy(kWifiRandomMacPolicyHardware, &ret));
    EXPECT_FALSE(service->SetMACPolicy(kWifiRandomMacPolicyFullRandom, &ret));
    EXPECT_FALSE(service->SetMACPolicy(kWifiRandomMacPolicyOUIRandom, &ret));
    EXPECT_FALSE(
        service->SetMACPolicy(kWifiRandomMacPolicyPersistentRandom, &ret));
    EXPECT_FALSE(
        service->SetMACPolicy(kWifiRandomMacPolicyNonPersistentRandom, &ret));
  }
}

TEST_F(WiFiServiceTest, SessionTagDefaultIsInvalid) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  // On creation, the session tag associated with the service is invalid.
  EXPECT_EQ(GetSessionTag(service), WiFiService::kSessionTagInvalid);
}

TEST_F(WiFiServiceTest, SessionTagCreatedNotInvalid) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  uint64_t session_tag;

  // After emitting a "connection attempt" event, the session tag is no longer
  // invalid.
  service->EmitConnectionAttemptEvent();
  session_tag = GetSessionTag(service);
  EXPECT_NE(session_tag, WiFiService::kSessionTagInvalid);
}

TEST_F(WiFiServiceTest, SessionTagNotReused) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  uint64_t session_tag1 = WiFiService::kSessionTagInvalid;
  uint64_t session_tag2 = WiFiService::kSessionTagInvalid;

  // When we emit 2 different "connection attempt" events it means they belong
  // to different sessions, therefore the tags are different.
  service->EmitConnectionAttemptEvent();
  session_tag1 = GetSessionTag(service);
  service->EmitConnectionAttemptEvent();
  session_tag2 = GetSessionTag(service);
  EXPECT_NE(session_tag1, session_tag2);
}

TEST_F(WiFiServiceTest, SessionTagConstantForFullSuccessfulConnection) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  uint64_t session_tag;

  // Emit a "connection attempt" event, which will create the session tag.
  service->EmitConnectionAttemptEvent();
  session_tag = GetSessionTag(service);
  // Connection attempt succeeded, the session tag is the same.
  service->EmitConnectionAttemptResultEvent(Service::kFailureNone);
  EXPECT_EQ(session_tag, GetSessionTag(service));
}

TEST_F(WiFiServiceTest, SessionTagInvalidAfterConnectionAttemptFailure) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);

  // Emit a "connection attempt" event, which will create the session tag.
  service->EmitConnectionAttemptEvent();
  // Connection attempt failed.
  service->EmitConnectionAttemptResultEvent(Service::kFailureBadPassphrase);
  // A failure to connect means that the session has ended, expect the session
  // tag to be reset to default.
  EXPECT_EQ(GetSessionTag(service), WiFiService::kSessionTagInvalid);
}

TEST_F(WiFiServiceTest, SessionTagInvalidAfterDisconnection) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);

  service->EmitConnectionAttemptEvent();
  // After a connection attempt, the tag is valid.
  EXPECT_NE(GetSessionTag(service), WiFiService::kSessionTagInvalid);
  service->EmitConnectionAttemptResultEvent(Service::kFailureNone);
  // After a successful connection, the session tag is still valid.
  EXPECT_NE(GetSessionTag(service), WiFiService::kSessionTagInvalid);
  service->EmitDisconnectionEvent(
      Metrics::kWiFiDisconnectionTypeExpectedUserAction,
      IEEE_80211::kReasonCodeTooManySTAs);
  // After disconnection the session has ended, expect the session tag to be
  // reset to default.
  EXPECT_EQ(GetSessionTag(service), WiFiService::kSessionTagInvalid);
}

TEST_F(WiFiServiceTest, ConnectionAttemptEmitsStructuredMetric) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);

  // When the service emits a connection attempt event, expect the metrics
  // object to receive the corresponding call.
  EXPECT_CALL(*metrics(), NotifyWiFiConnectionAttempt(_, _));
  service->EmitConnectionAttemptEvent();
}

TEST_F(WiFiServiceTest,
       ConnectionAttemptResultEmitsStructuredMetricWithTagOnSuccess) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  uint64_t session_tag;
  Service::ConnectFailure error = Service::kFailureNone;

  service->EmitConnectionAttemptEvent();
  session_tag = GetSessionTag(service);
  // The "connection attempt result" must have the same session tag as the
  // "connection attempt" event when the connection succeeded.
  EXPECT_CALL(*metrics(), NotifyWiFiConnectionAttemptResult(
                              Metrics::ConnectFailureToServiceErrorEnum(error),
                              session_tag));
  service->EmitConnectionAttemptResultEvent(error);
}

TEST_F(WiFiServiceTest,
       ConnectionAttemptResultEmitsStructuredMetricWithTagOnFailure) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  uint64_t session_tag;
  Service::ConnectFailure error = Service::kFailureBadPassphrase;

  service->EmitConnectionAttemptEvent();
  session_tag = GetSessionTag(service);
  // The "connection attempt result" must have the same session tag as the
  // "connection attempt" event when the connection failed.
  EXPECT_CALL(*metrics(), NotifyWiFiConnectionAttemptResult(
                              Metrics::ConnectFailureToServiceErrorEnum(error),
                              session_tag));
  service->EmitConnectionAttemptResultEvent(error);
}

TEST_F(WiFiServiceTest, DisconnectionEmitsStructuredMetricWithTagOnSuccess) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  uint64_t session_tag;
  Metrics::WiFiDisconnectionType disconnection_type =
      Metrics::kWiFiDisconnectionTypeExpectedUserAction;
  IEEE_80211::WiFiReasonCode error_code = IEEE_80211::kReasonCodeReserved0;

  service->EmitConnectionAttemptEvent();
  session_tag = GetSessionTag(service);
  service->EmitConnectionAttemptResultEvent(Service::kFailureNone);
  // The disconnection event must have the same session tag as the
  // "connection attempt" event when the disconnection is expected.
  EXPECT_CALL(*metrics(), NotifyWiFiDisconnection(disconnection_type,
                                                  error_code, session_tag));
  service->EmitDisconnectionEvent(disconnection_type, error_code);
}

TEST_F(WiFiServiceTest, DisconnectionEmitsStructuredMetricWithTagOnFailure) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  uint64_t session_tag;
  Metrics::WiFiDisconnectionType disconnection_type =
      Metrics::kWiFiDisconnectionTypeUnexpectedAPDisconnect;
  IEEE_80211::WiFiReasonCode error_code = IEEE_80211::kReasonCodeTooManySTAs;

  service->EmitConnectionAttemptEvent();
  session_tag = GetSessionTag(service);
  service->EmitConnectionAttemptResultEvent(Service::kFailureNone);
  // The disconnection event must have the same session tag as the
  // "connection attempt" event when the disconnection is unexpected.
  EXPECT_CALL(*metrics(), NotifyWiFiDisconnection(disconnection_type,
                                                  error_code, session_tag));
  service->EmitDisconnectionEvent(disconnection_type, error_code);
}

TEST_F(WiFiServiceTest, ConnectionAttemptValidTagUMA) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);

  // The session tag should be in the "expected" state.
  EXPECT_CALL(
      *metrics(),
      SendEnumToUMA(
          base::StringPrintf("%s.%s", Metrics::kWiFiSessionTagStateMetricPrefix,
                             Metrics::kWiFiSessionTagConnectionAttemptSuffix),
          Metrics::kWiFiSessionTagStateExpected,
          Metrics::kWiFiSessionTagStateMax));
  service->EmitConnectionAttemptEvent();
}

TEST_F(WiFiServiceTest, ConnectionAttemptInvalidTagUMA) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);

  // If we try to emit 2 "connection attempt" events in a row, the second one
  // should report that the session tag was unexpected.
  service->EmitConnectionAttemptEvent();
  EXPECT_CALL(
      *metrics(),
      SendEnumToUMA(
          base::StringPrintf("%s.%s", Metrics::kWiFiSessionTagStateMetricPrefix,
                             Metrics::kWiFiSessionTagConnectionAttemptSuffix),
          Metrics::kWiFiSessionTagStateUnexpected,
          Metrics::kWiFiSessionTagStateMax));
  // Second call will emit an "unexpected tag" UMA.
  service->EmitConnectionAttemptEvent();
}

TEST_F(WiFiServiceTest, ConnectionAttemptResultValidTagUMA) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);

  service->EmitConnectionAttemptEvent();
  EXPECT_CALL(
      *metrics(),
      SendEnumToUMA(base::StringPrintf(
                        "%s.%s", Metrics::kWiFiSessionTagStateMetricPrefix,
                        Metrics::kWiFiSessionTagConnectionAttemptResultSuffix),
                    Metrics::kWiFiSessionTagStateExpected,
                    Metrics::kWiFiSessionTagStateMax));
  // For a "connection attempt result" that happens immediately after a
  // "connection attempt", the state of the session tag should be expected.
  service->EmitConnectionAttemptResultEvent(Service::kFailureNone);
}

TEST_F(WiFiServiceTest, ConnectionAttemptResultInvalidTagUMA) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);

  EXPECT_CALL(
      *metrics(),
      SendEnumToUMA(base::StringPrintf(
                        "%s.%s", Metrics::kWiFiSessionTagStateMetricPrefix,
                        Metrics::kWiFiSessionTagConnectionAttemptResultSuffix),
                    Metrics::kWiFiSessionTagStateUnexpected,
                    Metrics::kWiFiSessionTagStateMax));
  // For a "connection attempt result" that happens without a corresponding
  // "connection attempt", the state of the session tag should be unexpected.
  service->EmitConnectionAttemptResultEvent(Service::kFailureNone);
}

TEST_F(WiFiServiceTest, DisconnectionValidTagUMA) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);

  service->EmitConnectionAttemptEvent();
  service->EmitConnectionAttemptResultEvent(Service::kFailureNone);
  EXPECT_CALL(
      *metrics(),
      SendEnumToUMA(
          base::StringPrintf("%s.%s", Metrics::kWiFiSessionTagStateMetricPrefix,
                             Metrics::kWiFiSessionTagDisconnectionSuffix),
          Metrics::kWiFiSessionTagStateExpected,
          Metrics::kWiFiSessionTagStateMax));
  // For the usual "connection attempt"->"connection attempt result"
  // ->"disconnection" sequence, the state of the session tag should be
  // expected.
  service->EmitDisconnectionEvent(
      Metrics::kWiFiDisconnectionTypeUnexpectedAPDisconnect,
      IEEE_80211::kReasonCodeTooManySTAs);
}

TEST_F(WiFiServiceTest, DisconnectionInvalidTagUMA) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);

  EXPECT_CALL(
      *metrics(),
      SendEnumToUMA(
          base::StringPrintf("%s.%s", Metrics::kWiFiSessionTagStateMetricPrefix,
                             Metrics::kWiFiSessionTagDisconnectionSuffix),
          Metrics::kWiFiSessionTagStateUnexpected,
          Metrics::kWiFiSessionTagStateMax));
  // For a "disconnection" event without a "connection attempt/result" event,
  // the state of the session tag should be unexpected.
  service->EmitDisconnectionEvent(
      Metrics::kWiFiDisconnectionTypeUnexpectedAPDisconnect,
      IEEE_80211::kReasonCodeTooManySTAs);
}

TEST_F(WiFiServiceTest, QualityLinkTriggerEmitsStructuredMetricWithTag) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  uint64_t session_tag;
  Metrics::WiFiLinkQualityTrigger trigger =
      Metrics::kWiFiLinkQualityTriggerCQMBeaconLoss;

  // We need a connection attempt for the tag to be valid.
  service->EmitConnectionAttemptEvent();
  session_tag = GetSessionTag(service);
  // The link quality trigger event must have the same session tag as the
  // "connection attempt" event.
  EXPECT_CALL(*metrics(), NotifyWiFiLinkQualityTrigger(trigger, session_tag));
  service->EmitLinkQualityTriggerEvent(trigger);
}

TEST_F(WiFiServiceTest, QualityLinkTriggerEmitsStructuredMetricWithInvalidTag) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  Metrics::WiFiLinkQualityTrigger trigger =
      Metrics::kWiFiLinkQualityTriggerCQMBeaconLoss;

  // If we have not attempted to connect yet, the session tag of the link
  // quality trigger event must be invalid.
  EXPECT_CALL(*metrics(), NotifyWiFiLinkQualityTrigger(
                              trigger, WiFiService::kSessionTagInvalid));
  service->EmitLinkQualityTriggerEvent(trigger);
}

TEST_F(WiFiServiceTest, QualityLinkTriggerValidTagUMA) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);

  // We need a connection attempt for the tag to be valid.
  service->EmitConnectionAttemptEvent();
  // For a "link quality trigger" event after a "connection attempt" event,
  // the state of the session tag should be "expected".
  EXPECT_CALL(
      *metrics(),
      SendEnumToUMA(
          base::StringPrintf("%s.%s", Metrics::kWiFiSessionTagStateMetricPrefix,
                             Metrics::kWiFiSessionTagLinkQualityTriggerSuffix),
          Metrics::kWiFiSessionTagStateExpected,
          Metrics::kWiFiSessionTagStateMax));
  service->EmitLinkQualityTriggerEvent(
      Metrics::kWiFiLinkQualityTriggerCQMRSSIHigh);
}

TEST_F(WiFiServiceTest, QualityLinkTriggerInvalidTagUMA) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);

  // For a "link quality trigger" event without a "connection attempt" event,
  // the state of the session tag should be "unexpected".
  EXPECT_CALL(
      *metrics(),
      SendEnumToUMA(
          base::StringPrintf("%s.%s", Metrics::kWiFiSessionTagStateMetricPrefix,
                             Metrics::kWiFiSessionTagLinkQualityTriggerSuffix),
          Metrics::kWiFiSessionTagStateUnexpected,
          Metrics::kWiFiSessionTagStateMax));
  service->EmitLinkQualityTriggerEvent(
      Metrics::kWiFiLinkQualityTriggerCQMBeaconLoss);
}

TEST_F(WiFiServiceTest, QualityLinkReportEmitsStructuredMetricWithTag) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  uint64_t session_tag;

  // We need a connection attempt for the tag to be valid.
  service->EmitConnectionAttemptEvent();
  session_tag = GetSessionTag(service);
  Metrics::WiFiLinkQualityReport report;
  // The link quality report event must have the same session tag as the
  // "connection attempt" event.
  EXPECT_CALL(*metrics(), NotifyWiFiLinkQualityReport(_, session_tag));
  service->EmitLinkQualityReportEvent(report);
}

TEST_F(WiFiServiceTest, CompareWithSameTechnology) {
  PasspointCredentialsRefPtr credentials = new PasspointCredentials("an_id");

  WiFiServiceRefPtr a = MakeServiceWithWiFi(kSecurityClass8021x);
  WiFiServiceRefPtr b = MakeServiceWithWiFi(kSecurityClass8021x);

  // a does not have Passpoint credentials while b have some
  b->set_parent_credentials(credentials);
  EXPECT_TRUE(SortingOrderIs(a, b));
  EXPECT_FALSE(SortingOrderIs(b, a));

  // a and be have Passpoint credentials but a different match priority
  a->set_parent_credentials(credentials);
  a->set_match_priority(3);
  b->set_match_priority(0);
  EXPECT_TRUE(SortingOrderIs(b, a));
  a->set_match_priority(1);
  b->set_match_priority(2);
  EXPECT_TRUE(SortingOrderIs(a, b));

  // Both have the same Passpoint credentials and the same priority, there will
  // be no order.
  a->set_match_priority(0);
  b->set_match_priority(0);
  EXPECT_FALSE(SortingOrderIs(a, b));
}

TEST_F(WiFiServiceTest, ConnectionAttemptInfoSuccess) {
  WiFiEndpointRefPtr ep = MakeOpenEndpoint("a", "00:00:00:00:00:01", 0, 0);
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  service->AddEndpoint(ep);

  Metrics::WiFiConnectionAttemptInfo info = GetConnectionAttemptInfo(service);
  EXPECT_EQ(info.ssid, "a");
  EXPECT_EQ(info.bssid, "00:00:00:00:00:01");
  EXPECT_EQ(info.security, Metrics::kWirelessSecurityNone);
}

TEST_F(WiFiServiceTest, ConnectionAttemptInfoNoBSSID) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  Metrics::WiFiConnectionAttemptInfo info = GetConnectionAttemptInfo(service);
  EXPECT_EQ(info.ap_oui, 0xFFFFFFFF);
}

TEST_F(WiFiServiceTest, ConnectionAttemptInfoOUI) {
  WiFiEndpointRefPtr ep = MakeOpenEndpoint("a", "01:23:45:67:89:ab", 0, 0);
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  service->AddEndpoint(ep);

  Metrics::WiFiConnectionAttemptInfo info = GetConnectionAttemptInfo(service);
  EXPECT_EQ(info.security, Metrics::kWirelessSecurityNone);
  if ((false)) {
    EXPECT_EQ(info.ap_oui, 0x00012345);
  }
}

TEST_F(WiFiServiceTest, ConnectionAttemptInfoLowBand) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);
  WiFiEndpoint::SecurityFlags flags;
  WiFiEndpointRefPtr ep =
      MakeEndpoint("a", "00:00:00:00:00:01", 2412, -57, flags);
  service->AddEndpoint(ep);

  Metrics::WiFiConnectionAttemptInfo info = GetConnectionAttemptInfo(service);
  EXPECT_EQ(info.band, Metrics::kWiFiFrequencyRange24);
  EXPECT_EQ(info.channel, Metrics::kWiFiChannel2412);
  EXPECT_EQ(info.rssi, -57);
}

TEST_F(WiFiServiceTest, ConnectionAttemptInfoHighBand) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);
  WiFiEndpoint::SecurityFlags flags;
  WiFiEndpointRefPtr ep =
      MakeEndpoint("a", "00:00:00:00:00:01", 5180, -71, flags);
  service->AddEndpoint(ep);

  Metrics::WiFiConnectionAttemptInfo info = GetConnectionAttemptInfo(service);
  EXPECT_EQ(info.band, Metrics::kWiFiFrequencyRange5);
  EXPECT_EQ(info.channel, Metrics::kWiFiChannel5180);
  EXPECT_EQ(info.rssi, -71);
}

TEST_F(WiFiServiceTest, ConnectionAttemptInfoUltraHighBand) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);
  WiFiEndpoint::SecurityFlags flags;
  WiFiEndpointRefPtr ep =
      MakeEndpoint("a", "00:00:00:00:00:01", 6115, -40, flags);
  service->AddEndpoint(ep);

  Metrics::WiFiConnectionAttemptInfo info = GetConnectionAttemptInfo(service);
  EXPECT_EQ(info.band, Metrics::kWiFiFrequencyRange6);
  EXPECT_EQ(info.channel, Metrics::kWiFiChannel6115);
  EXPECT_EQ(info.rssi, -40);
}

TEST_F(WiFiServiceTest, ConnectionAttemptInfoSecurity) {
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassPsk);
    WiFiEndpoint::SecurityFlags flags;
    flags.rsn_sae = true;
    WiFiEndpointRefPtr ep = MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(ep);

    Metrics::WiFiConnectionAttemptInfo info = GetConnectionAttemptInfo(service);
    EXPECT_EQ(Metrics::WiFiSecurityToEnum(WiFiSecurity::kWpa3), info.security);
  }
  {
    WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassPsk);
    WiFiEndpoint::SecurityFlags flags;
    flags.rsn_psk = true;
    WiFiEndpointRefPtr ep = MakeEndpoint("a", "00:00:00:00:00:01", 0, 0, flags);
    service->AddEndpoint(ep);
    Metrics::WiFiConnectionAttemptInfo info = GetConnectionAttemptInfo(service);
    EXPECT_EQ(Metrics::WiFiSecurityToEnum(WiFiSecurity::kWpa2), info.security);
  }
}

TEST_F(WiFiServiceTest, SetBSSIDAllowlist) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  EXPECT_CALL(*wifi(), SetBSSIDAllowlist(_, _, _)).WillRepeatedly(Return(true));
  Error error;

  // Default value
  std::vector<std::string> empty_list;
  EXPECT_EQ(empty_list, service->GetBSSIDAllowlist(&error));

  // Set some values
  std::vector<std::string> bssid_allowlist = {"aa:bb:cc:dd:ee:ff"};
  EXPECT_TRUE(service->SetBSSIDAllowlist(bssid_allowlist, &error));
  EXPECT_EQ(bssid_allowlist, service->GetBSSIDAllowlist(&error));

  // Setting the same allowlist returns false
  EXPECT_FALSE(service->SetBSSIDAllowlist(bssid_allowlist, &error));
  EXPECT_EQ(bssid_allowlist, service->GetBSSIDAllowlist(&error));

  // Set back to empty list is ok
  bssid_allowlist = {};
  EXPECT_TRUE(service->SetBSSIDAllowlist(bssid_allowlist, &error));
  EXPECT_EQ(bssid_allowlist, service->GetBSSIDAllowlist(&error));

  // Single value of zeroes is ok
  std::vector<std::string> zeroes_bssid_allowlist = {"00:00:00:00:00:00"};
  EXPECT_TRUE(service->SetBSSIDAllowlist(zeroes_bssid_allowlist, &error));
  EXPECT_EQ(zeroes_bssid_allowlist, service->GetBSSIDAllowlist(&error));

  // We should filter out dupes
  std::vector<std::string> duped_bssid_allowlist = {
      "00:00:00:00:00:01", "00:00:00:00:00:01", "00:00:00:00:00:02"};
  std::vector<std::string> not_duped_bssid_allowlist = {"00:00:00:00:00:01",
                                                        "00:00:00:00:00:02"};
  EXPECT_TRUE(service->SetBSSIDAllowlist(duped_bssid_allowlist, &error));
  EXPECT_EQ(not_duped_bssid_allowlist, service->GetBSSIDAllowlist(&error));

  // Unparsable hardware address
  std::vector<std::string> invalid_values = {"foo"};
  EXPECT_FALSE(service->SetBSSIDAllowlist(invalid_values, &error));
  EXPECT_TRUE(error.type() == Error::kInvalidArguments);

  // Can't have zeroes and non-zeroes values at the same time
  std::vector<std::string> non_zeroes_bssid_allowlist = {"00:00:00:00:00:00",
                                                         "aa:bb:cc:dd:ee:ff"};
  EXPECT_FALSE(service->SetBSSIDAllowlist(non_zeroes_bssid_allowlist, &error));
  EXPECT_TRUE(error.type() == Error::kInvalidArguments);

  // Can't have multiple zeroes
  zeroes_bssid_allowlist = {"00:00:00:00:00:00", "00:00:00:00:00:00"};
  EXPECT_TRUE(service->SetBSSIDAllowlist(zeroes_bssid_allowlist, &error));
  EXPECT_TRUE(error.type() == Error::kInvalidArguments);

  // If we fail to set it in |wifi|, bssid_allowlist doesn't change
  bssid_allowlist = {};
  EXPECT_TRUE(service->SetBSSIDAllowlist(bssid_allowlist, &error));
  EXPECT_EQ(bssid_allowlist, service->GetBSSIDAllowlist(&error));

  Mock::VerifyAndClearExpectations(wifi().get());
  EXPECT_CALL(*wifi(), SetBSSIDAllowlist(_, _, _))
      .WillRepeatedly(Return(false));

  std::vector<std::string> new_bssid_allowlist = {"00:00:00:00:00:01"};
  EXPECT_FALSE(service->SetBSSIDAllowlist(new_bssid_allowlist, &error));
  EXPECT_EQ(bssid_allowlist, service->GetBSSIDAllowlist(&error));
}

TEST_F(WiFiServiceTest, BSSIDConnectableEndpoints) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);

  // No endpoints and no allowlist still means nothing is connectable
  EXPECT_EQ(0, service->GetBSSIDConnectableEndpointCount());
  EXPECT_FALSE(service->HasBSSIDConnectableEndpoints());

  // By default, an endpoint is potentially connectable
  WiFiEndpoint::SecurityFlags flags;
  WiFiEndpointRefPtr endpoint = MakeEndpoint(
      "a", "00:00:00:00:00:01", /*frequency=*/0, /*signal_dbm=*/0, flags);
  service->AddEndpoint(endpoint);
  EXPECT_EQ(1, service->GetBSSIDConnectableEndpointCount());
  EXPECT_TRUE(service->HasBSSIDConnectableEndpoints());
}

TEST_F(WiFiServiceTest, NoBSSIDConnectableEndpoints) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);
  EXPECT_CALL(*wifi(), SetBSSIDAllowlist(_, _, _)).WillRepeatedly(Return(true));

  WiFiEndpoint::SecurityFlags flags;
  WiFiEndpointRefPtr endpoint = MakeEndpoint(
      "a", "aa:bb:cc:dd:ee:ff", /*frequency=*/0, /*signal_dbm=*/0, flags);
  service->AddEndpoint(endpoint);

  EXPECT_EQ(1, service->GetBSSIDConnectableEndpointCount());
  EXPECT_TRUE(service->HasBSSIDConnectableEndpoints());
  EXPECT_TRUE(service->IsBSSIDConnectable(endpoint));

  std::vector<std::string> bssid_allowlist = {"00:00:00:00:00:00"};
  Error error;
  EXPECT_TRUE(service->SetBSSIDAllowlist(bssid_allowlist, &error));
  EXPECT_EQ(0, service->GetBSSIDConnectableEndpointCount());
  EXPECT_FALSE(service->HasBSSIDConnectableEndpoints());
  EXPECT_FALSE(service->IsBSSIDConnectable(endpoint));

  bssid_allowlist = {"00:00:00:00:00:01"};
  EXPECT_TRUE(service->SetBSSIDAllowlist(bssid_allowlist, &error));
  EXPECT_EQ(0, service->GetBSSIDConnectableEndpointCount());
  EXPECT_FALSE(service->HasBSSIDConnectableEndpoints());
  EXPECT_FALSE(service->IsBSSIDConnectable(endpoint));
}

TEST_F(WiFiServiceTest, AllowlistedBSSIDConnectableEndpoints) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);
  EXPECT_CALL(*wifi(), SetBSSIDAllowlist(_, _, _)).WillRepeatedly(Return(true));

  WiFiEndpoint::SecurityFlags flags;
  WiFiEndpointRefPtr endpoint = MakeEndpoint(
      "a", "aa:bb:cc:dd:ee:ff", /*frequency=*/0, /*signal_dbm=*/0, flags);
  service->AddEndpoint(endpoint);

  EXPECT_EQ(1, service->GetBSSIDConnectableEndpointCount());
  EXPECT_TRUE(service->HasBSSIDConnectableEndpoints());
  EXPECT_TRUE(service->IsBSSIDConnectable(endpoint));

  // Allowlist matches endpoints
  std::vector<std::string> bssid_allowlist = {"aa:bb:cc:dd:ee:ff"};
  Error error;
  EXPECT_TRUE(service->SetBSSIDAllowlist(bssid_allowlist, &error));

  EXPECT_EQ(1, service->GetBSSIDConnectableEndpointCount());
  EXPECT_TRUE(service->HasBSSIDConnectableEndpoints());
  EXPECT_TRUE(service->IsBSSIDConnectable(endpoint));

  // Extra allowlisted BSSIDs don't affect anything
  bssid_allowlist = {"00:00:00:00:00:01", "aa:bb:cc:dd:ee:ff"};
  EXPECT_TRUE(service->SetBSSIDAllowlist(bssid_allowlist, &error));

  EXPECT_EQ(1, service->GetBSSIDConnectableEndpointCount());
  EXPECT_TRUE(service->HasBSSIDConnectableEndpoints());
  EXPECT_TRUE(service->IsBSSIDConnectable(endpoint));
}

TEST_F(WiFiServiceTest, SetBSSIDRequested) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);
  Error error;

  // Default value
  EXPECT_EQ("", service->GetBSSIDRequested(&error));

  // Set arbitrary value
  EXPECT_TRUE(service->SetBSSIDRequested("00:00:00:00:00:00", &error));
  EXPECT_EQ("00:00:00:00:00:00", service->GetBSSIDRequested(&error));

  // Set same value
  EXPECT_FALSE(service->SetBSSIDRequested("00:00:00:00:00:00", &error));

  // Unparsable hardware address
  EXPECT_FALSE(service->SetBSSIDRequested("foo", &error));
  EXPECT_TRUE(error.type() == Error::kInvalidArguments);

  // Empty string
  EXPECT_TRUE(service->SetBSSIDRequested("", &error));
}

TEST_F(WiFiServiceTest, BSSIDRequestedToSupplicant) {
  WiFiServiceRefPtr service = MakeServiceWithWiFi(kSecurityClassNone);

  // If not set, the requested BSSID won't be set in the supplicant params
  KeyValueStore params = service->GetSupplicantConfigurationParameters();
  EXPECT_FALSE(
      params.Contains<std::string>(WPASupplicant::kNetworkPropertyBSSID));

  // Non-empty values should be present though
  Error unused_error;
  service->SetBSSIDRequested("00:00:00:00:00:01", &unused_error);
  params = service->GetSupplicantConfigurationParameters();
  EXPECT_TRUE(
      params.Contains<std::string>(WPASupplicant::kNetworkPropertyBSSID));
}

TEST_F(WiFiServiceTest, BSSIDRequestedConnectableEndpoints) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);
  Error error;

  WiFiEndpoint::SecurityFlags flags;
  WiFiEndpointRefPtr endpoint = MakeEndpoint(
      "a", "aa:bb:cc:dd:ee:ff", /*frequency=*/0, /*signal_dbm=*/0, flags);
  service->AddEndpoint(endpoint);

  EXPECT_EQ(1, service->GetBSSIDConnectableEndpointCount());
  EXPECT_TRUE(service->HasBSSIDConnectableEndpoints());
  EXPECT_TRUE(service->IsBSSIDConnectable(endpoint));

  // Request specific BSSID that's also in |endpoints|
  EXPECT_TRUE(service->SetBSSIDRequested("aa:bb:cc:dd:ee:ff", &error));

  EXPECT_EQ(1, service->GetBSSIDConnectableEndpointCount());
  EXPECT_TRUE(service->HasBSSIDConnectableEndpoints());
  EXPECT_TRUE(service->IsBSSIDConnectable(endpoint));

  // Request specific BSSID that's not in |endpoints|
  EXPECT_TRUE(service->SetBSSIDRequested("00:00:00:00:00:01", &error));

  EXPECT_EQ(0, service->GetBSSIDConnectableEndpointCount());
  EXPECT_FALSE(service->HasBSSIDConnectableEndpoints());
  EXPECT_FALSE(service->IsBSSIDConnectable(endpoint));
}

TEST_F(WiFiServiceTest, BSSIDRequestedAndAllowlistedConnectableEndpoints) {
  WiFiServiceRefPtr service = MakeSimpleService(kSecurityClassNone);
  EXPECT_CALL(*wifi(), SetBSSIDAllowlist(_, _, _)).WillRepeatedly(Return(true));
  Error error;

  WiFiEndpoint::SecurityFlags flags;
  WiFiEndpointRefPtr endpoint = MakeEndpoint(
      "a", "aa:bb:cc:dd:ee:ff", /*frequency=*/0, /*signal_dbm=*/0, flags);
  service->AddEndpoint(endpoint);

  // |endpoint| is requested and in the allowlist
  EXPECT_TRUE(service->SetBSSIDRequested("aa:bb:cc:dd:ee:ff", &error));
  std::vector<std::string> bssid_allowlist = {"aa:bb:cc:dd:ee:ff"};
  EXPECT_TRUE(service->SetBSSIDAllowlist(bssid_allowlist, &error));

  EXPECT_EQ(1, service->GetBSSIDConnectableEndpointCount());
  EXPECT_TRUE(service->HasBSSIDConnectableEndpoints());
  EXPECT_TRUE(service->IsBSSIDConnectable(endpoint));

  // |endpoint| is requested, but not in the allowlist
  service->SetBSSIDRequested("aa:bb:cc:dd:ee:ff", &error);
  bssid_allowlist = {"00:00:00:00:00:01"};
  service->SetBSSIDAllowlist(bssid_allowlist, &error);

  EXPECT_EQ(0, service->GetBSSIDConnectableEndpointCount());
  EXPECT_FALSE(service->HasBSSIDConnectableEndpoints());
  EXPECT_FALSE(service->IsBSSIDConnectable(endpoint));

  // |endpoint| is in the allowlist, but not requested
  service->SetBSSIDRequested("00:00:00:00:00:01", &error);
  bssid_allowlist = {"aa:bb:cc:dd:ee:ff"};
  service->SetBSSIDAllowlist(bssid_allowlist, &error);

  EXPECT_EQ(0, service->GetBSSIDConnectableEndpointCount());
  EXPECT_FALSE(service->HasBSSIDConnectableEndpoints());
  EXPECT_FALSE(service->IsBSSIDConnectable(endpoint));

  // |endpoint| is requested, but allowlist is all zeroes (i.e. nothing is
  // connectable)
  service->SetBSSIDRequested("aa:bb:cc:dd:ee:ff", &error);
  bssid_allowlist = {"00:00:00:00:00:00"};
  service->SetBSSIDAllowlist(bssid_allowlist, &error);

  EXPECT_EQ(0, service->GetBSSIDConnectableEndpointCount());
  EXPECT_FALSE(service->HasBSSIDConnectableEndpoints());
  EXPECT_FALSE(service->IsBSSIDConnectable(endpoint));
}

}  // namespace shill
