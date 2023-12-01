// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/vpn_driver.h"

#include <iterator>
#include <vector>

#include <base/strings/string_number_conversions.h>
#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/mock_control.h"
#include "shill/mock_device_info.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_service.h"
#include "shill/store/fake_store.h"
#include "shill/store/property_store.h"
#include "shill/test_event_dispatcher.h"

using testing::_;
using testing::NiceMock;
using testing::Return;
using testing::Test;

namespace shill {

namespace {

const char kVPNHostProperty[] = "VPN.Host";
const char kOTPProperty[] = "VPN.OTP";
const char kPinProperty[] = "VPN.PIN";
const char kPSKProperty[] = "VPN.PSK";
const char kPasswordProperty[] = "VPN.Password";
const char kPortProperty[] = "VPN.Port";

const char kPin[] = "5555";
const char kPassword[] = "random-password";
const char kPort[] = "1234";
const char kStorageID[] = "vpn_service_id";

}  // namespace

class VPNDriverUnderTest : public VPNDriver {
 public:
  explicit VPNDriverUnderTest(Manager* manager);
  VPNDriverUnderTest(const VPNDriverUnderTest&) = delete;
  VPNDriverUnderTest& operator=(const VPNDriverUnderTest&) = delete;

  ~VPNDriverUnderTest() override = default;

  // Inherited from VPNDriver.
  MOCK_METHOD(base::TimeDelta, ConnectAsync, (EventHandler*), (override));
  MOCK_METHOD(void, Disconnect, (), (override));
  MOCK_METHOD(void, OnConnectTimeout, (), (override));
  MOCK_METHOD(std::unique_ptr<IPConfig::Properties>,
              GetIPv4Properties,
              (),
              (const, override));
  MOCK_METHOD(std::unique_ptr<IPConfig::Properties>,
              GetIPv6Properties,
              (),
              (const, override));

 private:
  static const Property kProperties[];
};

// static
const VPNDriverUnderTest::Property VPNDriverUnderTest::kProperties[] = {
    {kEapCaCertPemProperty, Property::kArray},
    {kVPNHostProperty, 0},
    {kL2TPIPsecCaCertPemProperty, Property::kArray},
    {kOTPProperty, Property::kEphemeral},
    {kPinProperty, Property::kWriteOnly},
    {kPSKProperty, Property::kCredential},
    {kPasswordProperty, Property::kCredential},
    {kPortProperty, 0},
    {kProviderTypeProperty, 0},
};

VPNDriverUnderTest::VPNDriverUnderTest(Manager* manager)
    : VPNDriver(manager,
                nullptr,
                VPNType::kIKEv2,
                kProperties,
                std::size(kProperties)) {}

class VPNDriverTest : public Test {
 public:
  VPNDriverTest()
      : manager_(&control_, &dispatcher_, &metrics_),
        device_info_(&manager_),
        driver_(&manager_) {}

  ~VPNDriverTest() override = default;

 protected:
  std::string credential_prefix() const { return VPNDriver::kCredentialPrefix; }

  void SetArg(const std::string& arg, const std::string& value) {
    driver_.args()->Set<std::string>(arg, value);
  }

  void SetArgArray(const std::string& arg,
                   const std::vector<std::string>& value) {
    driver_.args()->Set<Strings>(arg, value);
  }

  KeyValueStore* GetArgs() { return driver_.args(); }

  bool GetProviderPropertyString(const PropertyStore& store,
                                 const std::string& key,
                                 std::string* value);

  bool GetProviderPropertyStrings(const PropertyStore& store,
                                  const std::string& key,
                                  std::vector<std::string>* value);

  MockControl control_;
  EventDispatcherForTest dispatcher_;
  MockMetrics metrics_;
  MockManager manager_;
  NiceMock<MockDeviceInfo> device_info_;
  VPNDriverUnderTest driver_;
};

bool VPNDriverTest::GetProviderPropertyString(const PropertyStore& store,
                                              const std::string& key,
                                              std::string* value) {
  KeyValueStore provider_properties;
  Error error;
  EXPECT_TRUE(store.GetKeyValueStoreProperty(kProviderProperty,
                                             &provider_properties, &error));
  if (!provider_properties.Contains<std::string>(key)) {
    return false;
  }
  if (value != nullptr) {
    *value = provider_properties.Get<std::string>(key);
  }
  return true;
}

bool VPNDriverTest::GetProviderPropertyStrings(
    const PropertyStore& store,
    const std::string& key,
    std::vector<std::string>* value) {
  KeyValueStore provider_properties;
  Error error;
  EXPECT_TRUE(store.GetKeyValueStoreProperty(kProviderProperty,
                                             &provider_properties, &error));
  if (!provider_properties.Contains<Strings>(key)) {
    return false;
  }
  if (value != nullptr) {
    *value = provider_properties.Get<Strings>(key);
  }
  return true;
}

TEST_F(VPNDriverTest, Load) {
  FakeStore storage;
  GetArgs()->Set<std::string>(kVPNHostProperty, "1.2.3.4");
  GetArgs()->Set<std::string>(kPSKProperty, "1234");
  GetArgs()->Set<Strings>(kL2TPIPsecCaCertPemProperty,
                          {"cleared-cert0", "cleared-cert1"});
  std::vector<std::string> kCaCerts{"cert0", "cert1"};
  storage.SetStringList(kStorageID, kEapCaCertPemProperty, kCaCerts);
  storage.SetString(kStorageID, kPortProperty, kPort);
  storage.SetString(kStorageID, kPinProperty, kPin);
  storage.SetString(kStorageID, credential_prefix() + kPasswordProperty,
                    kPassword);

  EXPECT_TRUE(driver_.Load(&storage, kStorageID));

  EXPECT_EQ(kCaCerts, GetArgs()->Get<Strings>(kEapCaCertPemProperty));
  EXPECT_EQ(kPort, GetArgs()->Lookup<std::string>(kPortProperty, ""));
  EXPECT_EQ(kPin, GetArgs()->Lookup<std::string>(kPinProperty, ""));
  EXPECT_EQ(kPassword, GetArgs()->Lookup<std::string>(kPasswordProperty, ""));

  // Properties missing from the persistent store should be deleted.
  EXPECT_FALSE(GetArgs()->Contains<std::string>(kVPNHostProperty));
  EXPECT_FALSE(GetArgs()->Contains<Strings>(kL2TPIPsecCaCertPemProperty));
  EXPECT_FALSE(GetArgs()->Contains<std::string>(kPSKProperty));
}

TEST_F(VPNDriverTest, Save) {
  SetArg(kProviderTypeProperty, kProviderOpenVpn);
  SetArg(kPinProperty, kPin);
  SetArg(kPortProperty, kPort);
  SetArg(kPasswordProperty, kPassword);
  SetArg(kOTPProperty, "987654");
  const std::vector<std::string> kCaCerts{"cert0", "cert1"};
  SetArgArray(kEapCaCertPemProperty, kCaCerts);

  FakeStore storage;
  EXPECT_TRUE(driver_.Save(&storage, kStorageID, true));

  std::vector<std::string> ca_pem;
  std::string provider_type, port, pin, password;
  EXPECT_TRUE(
      storage.GetStringList(kStorageID, kEapCaCertPemProperty, &ca_pem));
  EXPECT_EQ(ca_pem, kCaCerts);
  EXPECT_TRUE(
      storage.GetString(kStorageID, kProviderTypeProperty, &provider_type));
  EXPECT_EQ(provider_type, kProviderOpenVpn);
  EXPECT_TRUE(storage.GetString(kStorageID, kPortProperty, &port));
  EXPECT_EQ(port, kPort);
  EXPECT_TRUE(storage.GetString(kStorageID, kPinProperty, &pin));
  EXPECT_EQ(pin, kPin);
  EXPECT_TRUE(storage.GetString(
      kStorageID, credential_prefix() + kPasswordProperty, &password));
  EXPECT_EQ(password, kPassword);

  EXPECT_FALSE(storage.GetString(kStorageID, credential_prefix() + kPSKProperty,
                                 nullptr));
}

TEST_F(VPNDriverTest, SaveNoCredentials) {
  SetArg(kPasswordProperty, kPassword);
  SetArg(kPSKProperty, "");

  FakeStore storage;
  EXPECT_TRUE(driver_.Save(&storage, kStorageID, false));

  EXPECT_FALSE(storage.GetString(
      kStorageID, credential_prefix() + kPasswordProperty, nullptr));
  EXPECT_FALSE(storage.GetString(kStorageID, credential_prefix() + kPSKProperty,
                                 nullptr));
  EXPECT_FALSE(storage.GetString(kStorageID, kEapCaCertPemProperty, nullptr));
  EXPECT_FALSE(
      storage.GetString(kStorageID, kL2TPIPsecCaCertPemProperty, nullptr));
}

TEST_F(VPNDriverTest, UnloadCredentials) {
  SetArg(kOTPProperty, "654321");
  SetArg(kPasswordProperty, kPassword);
  SetArg(kPortProperty, kPort);
  driver_.UnloadCredentials();
  EXPECT_FALSE(GetArgs()->Contains<std::string>(kOTPProperty));
  EXPECT_FALSE(GetArgs()->Contains<std::string>(kPasswordProperty));
  EXPECT_EQ(kPort, GetArgs()->Lookup<std::string>(kPortProperty, ""));
}

TEST_F(VPNDriverTest, InitPropertyStore) {
  // Figure out if the store is actually hooked up to the driver argument
  // KeyValueStore.
  PropertyStore store;
  driver_.InitPropertyStore(&store);

  // An un-set property should not be readable.
  {
    Error error;
    EXPECT_FALSE(store.GetStringProperty(kPortProperty, nullptr, &error));
    EXPECT_EQ(Error::kInvalidArguments, error.type());
  }
  {
    Error error;
    EXPECT_FALSE(
        store.GetStringsProperty(kEapCaCertPemProperty, nullptr, &error));
    EXPECT_EQ(Error::kInvalidArguments, error.type());
  }
  EXPECT_FALSE(GetProviderPropertyString(store, kPortProperty, nullptr));
  EXPECT_FALSE(
      GetProviderPropertyStrings(store, kEapCaCertPemProperty, nullptr));

  const std::string kProviderType = "boo";
  SetArg(kPortProperty, kPort);
  SetArg(kPasswordProperty, kPassword);
  SetArg(kProviderTypeProperty, kProviderType);
  SetArg(kVPNHostProperty, "");
  const std::vector<std::string> kCaCerts{"cert1"};
  SetArgArray(kEapCaCertPemProperty, kCaCerts);
  SetArgArray(kL2TPIPsecCaCertPemProperty, std::vector<std::string>());

  // We should not be able to read a property out of the driver args using the
  // key to the args directly.
  {
    Error error;
    EXPECT_FALSE(store.GetStringProperty(kPortProperty, nullptr, &error));
    EXPECT_EQ(Error::kInvalidArguments, error.type());
  }
  {
    Error error;
    EXPECT_FALSE(
        store.GetStringsProperty(kEapCaCertPemProperty, nullptr, &error));
    EXPECT_EQ(Error::kInvalidArguments, error.type());
  }

  // We should instead be able to find it within the "Provider" stringmap.
  {
    std::string value;
    EXPECT_TRUE(GetProviderPropertyString(store, kPortProperty, &value));
    EXPECT_EQ(kPort, value);
  }
  {
    std::vector<std::string> value;
    EXPECT_TRUE(
        GetProviderPropertyStrings(store, kEapCaCertPemProperty, &value));
    EXPECT_EQ(kCaCerts, value);
  }

  // We should be able to read empty properties from the "Provider" stringmap.
  {
    std::string value;
    EXPECT_TRUE(GetProviderPropertyString(store, kVPNHostProperty, &value));
    EXPECT_TRUE(value.empty());
  }
  {
    std::vector<std::string> value;
    EXPECT_TRUE(
        GetProviderPropertyStrings(store, kL2TPIPsecCaCertPemProperty, &value));
    EXPECT_TRUE(value.empty());
  }

  // Properties that start with the prefix "Provider." should be mapped to the
  // name in the Properties dict with the prefix removed.
  {
    std::string value;
    EXPECT_TRUE(GetProviderPropertyString(store, kTypeProperty, &value));
    EXPECT_EQ(kProviderType, value);
  }

  // If we clear a property, we should no longer be able to find it.
  {
    Error error;
    EXPECT_TRUE(store.ClearProperty(kPortProperty, &error));
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_FALSE(GetProviderPropertyString(store, kPortProperty, nullptr));
  }
  {
    Error error;
    EXPECT_TRUE(store.ClearProperty(kEapCaCertPemProperty, &error));
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_FALSE(
        GetProviderPropertyStrings(store, kEapCaCertPemProperty, nullptr));
  }

  // A second attempt to clear this property should return an error.
  {
    Error error;
    EXPECT_FALSE(store.ClearProperty(kPortProperty, &error));
    EXPECT_EQ(Error::kNotFound, error.type());
  }
  {
    Error error;
    EXPECT_FALSE(store.ClearProperty(kEapCaCertPemProperty, &error));
    EXPECT_EQ(Error::kNotFound, error.type());
  }

  // Test write only properties.
  EXPECT_FALSE(GetProviderPropertyString(store, kPinProperty, nullptr));

  // Write properties to the driver args using the PropertyStore interface.
  {
    const std::string kValue = "some-value";
    Error error;
    store.SetStringProperty(kPinProperty, kValue, &error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(kValue, GetArgs()->Get<std::string>(kPinProperty));
  }
  {
    const std::vector<std::string> kValue{"some-value"};
    Error error;
    store.SetStringsProperty(kEapCaCertPemProperty, kValue, &error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(kValue, GetArgs()->Get<Strings>(kEapCaCertPemProperty));
  }
}

}  // namespace shill
