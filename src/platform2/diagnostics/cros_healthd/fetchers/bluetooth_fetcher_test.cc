// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <vector>

#include <dbus/object_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/fetchers/bluetooth_fetcher.h"
#include "diagnostics/cros_healthd/system/mock_bluetooth_info_manager.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/dbus_bindings/bluetooth/dbus-proxy-mocks.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::StrictMock;

std::unique_ptr<org::bluez::Adapter1Proxy::PropertySet> GetAdapterProperties() {
  auto properties = std::make_unique<org::bluez::Adapter1Proxy::PropertySet>(
      nullptr, base::BindRepeating([](const std::string& property_name) {}));
  properties->address.ReplaceValue("aa:bb:cc:dd:ee:ff");
  properties->name.ReplaceValue("sarien-laptop");
  properties->powered.ReplaceValue(true);
  properties->discoverable.ReplaceValue(true);
  properties->discovering.ReplaceValue(true);
  properties->uuids.ReplaceValue({"0000110e-0000-1000-8000-00805f9b34fb",
                                  "0000111f-0000-1000-8000-00805f9b34fb",
                                  "0000110c-0000-1000-8000-00805f9b34fb"});
  properties->modalias.ReplaceValue("bluetooth:v00E0pC405d0067");
  return properties;
}

std::unique_ptr<org::bluez::Device1Proxy::PropertySet> GetDeviceProperties() {
  auto properties = std::make_unique<org::bluez::Device1Proxy::PropertySet>(
      nullptr, base::BindRepeating([](const std::string& property_name) {}));
  properties->connected.ReplaceValue(true);
  properties->address.ReplaceValue("70:88:6B:92:34:70");
  properties->name.ReplaceValue("GID6B");
  properties->type.ReplaceValue("BR/EDR");
  properties->appearance.ReplaceValue(2371);
  properties->modalias.ReplaceValue("bluetooth:v000ApFFFFdFFFF");
  properties->rssi.ReplaceValue(-55);
  properties->mtu.ReplaceValue(12320);
  properties->uuids.ReplaceValue({"00001107-d102-11e1-9b23-00025b00a5a5",
                                  "0000110c-0000-1000-8000-00805f9b34fb",
                                  "0000110e-0000-1000-8000-00805f9b34fb",
                                  "0000111e-0000-1000-8000-00805f9b34fb",
                                  "f8d1fbe4-7966-4334-8024-ff96c9330e15"});
  properties->bluetooth_class.ReplaceValue(2360344);
  return properties;
}

std::unique_ptr<org::bluez::AdminPolicyStatus1Proxy::PropertySet>
GetAdapterPolicyProperties() {
  auto properties =
      std::make_unique<org::bluez::AdminPolicyStatus1Proxy::PropertySet>(
          nullptr,
          base::BindRepeating([](const std::string& property_name) {}));
  properties->service_allow_list.ReplaceValue(
      {"0000110b-0000-1000-8000-00805f9b34fb",
       "0000110d-0000-1000-8000-00805f9b34fb"});
  return properties;
}

std::unique_ptr<org::bluez::LEAdvertisingManager1Proxy::PropertySet>
GetAdapterAdvertisingProperties() {
  auto properties =
      std::make_unique<org::bluez::LEAdvertisingManager1Proxy::PropertySet>(
          nullptr,
          base::BindRepeating([](const std::string& property_name) {}));

  properties->supported_capabilities.ReplaceValue(
      {{"MaxAdvLen", static_cast<uint8_t>(31)},
       {"MaxScnRspLen", static_cast<uint8_t>(31)},
       {"MinTxPower", static_cast<int16_t>(-34)},
       {"MaxTxPower", static_cast<int16_t>(7)}});
  return properties;
}

std::unique_ptr<org::bluez::Battery1Proxy::PropertySet>
GetDeviceBatteryProperties() {
  auto properties = std::make_unique<org::bluez::Battery1Proxy::PropertySet>(
      nullptr, base::BindRepeating([](const std::string& property_name) {}));
  properties->percentage.ReplaceValue(80);
  return properties;
}

// Convert |BluetoothDeviceType| enum to string.
std::string ConvertDeviceType(mojom::BluetoothDeviceType type) {
  switch (type) {
    case mojom::BluetoothDeviceType::kBrEdr:
      return "BR/EDR";
    case mojom::BluetoothDeviceType::kLe:
      return "LE";
    case mojom::BluetoothDeviceType::kDual:
      return "DUAL";
    case mojom::BluetoothDeviceType::kUnfound:
    case mojom::BluetoothDeviceType::kUnmappedEnumField:
      NOTREACHED();
      return "";
  }
}

class BluetoothFetcherTest : public ::testing::Test {
 protected:
  BluetoothFetcherTest() = default;
  BluetoothFetcherTest(const BluetoothFetcherTest&) = delete;
  BluetoothFetcherTest& operator=(const BluetoothFetcherTest&) = delete;
  ~BluetoothFetcherTest() = default;

  const dbus::ObjectPath& adapter_path() { return adapter_path_; }
  const dbus::ObjectPath& device_path() { return device_path_; }

  MockContext* mock_context() { return &mock_context_; }
  MockBluetoothInfoManager* mock_bluetooth_info_manager() {
    return mock_context_.mock_bluetooth_info_manager();
  }

  // Getter of mock proxy.
  org::bluez::Adapter1ProxyMock* mock_adapter_proxy() const {
    return static_cast<StrictMock<org::bluez::Adapter1ProxyMock>*>(
        adapter_proxy_.get());
  }
  org::bluez::Device1ProxyMock* mock_device_proxy() const {
    return static_cast<StrictMock<org::bluez::Device1ProxyMock>*>(
        device_proxy_.get());
  }
  org::bluez::AdminPolicyStatus1ProxyMock* mock_admin_policy_proxy() const {
    return static_cast<StrictMock<org::bluez::AdminPolicyStatus1ProxyMock>*>(
        admin_policy_proxy_.get());
  }
  org::bluez::LEAdvertisingManager1ProxyMock* mock_advertising_proxy() const {
    return static_cast<StrictMock<org::bluez::LEAdvertisingManager1ProxyMock>*>(
        advertising_proxy_.get());
  }
  org::bluez::Battery1ProxyMock* mock_battery_proxy() const {
    return static_cast<StrictMock<org::bluez::Battery1ProxyMock>*>(
        battery_proxy_.get());
  }

  // Set up function call in mock object.
  void SetMockAdapterProxyCall(
      const std::unique_ptr<org::bluez::Adapter1Proxy::PropertySet>&
          adapter_properties) {
    EXPECT_CALL(*mock_adapter_proxy(), name())
        .WillOnce(ReturnRef(adapter_properties->name.value()));
    EXPECT_CALL(*mock_adapter_proxy(), address())
        .WillOnce(ReturnRef(adapter_properties->address.value()));
    EXPECT_CALL(*mock_adapter_proxy(), powered())
        .WillOnce(Return(adapter_properties->powered.value()));
    EXPECT_CALL(*mock_adapter_proxy(), discoverable())
        .WillOnce(Return(adapter_properties->discoverable.value()));
    EXPECT_CALL(*mock_adapter_proxy(), discovering())
        .WillOnce(Return(adapter_properties->discovering.value()));
    EXPECT_CALL(*mock_adapter_proxy(), uuids())
        .WillOnce(ReturnRef(adapter_properties->uuids.value()));
    EXPECT_CALL(*mock_adapter_proxy(), modalias())
        .WillOnce(ReturnRef(adapter_properties->modalias.value()));
    EXPECT_CALL(*mock_adapter_proxy(), GetObjectPath())
        .WillOnce(ReturnRef(adapter_path()));
  }
  void SetMockDeviceProxyCall(
      const std::unique_ptr<org::bluez::Device1Proxy::PropertySet>&
          device_properties,
      int device_call_times) {
    EXPECT_CALL(*mock_device_proxy(), connected())
        .Times(device_call_times)
        .WillRepeatedly(Return(device_properties->connected.value()));
    EXPECT_CALL(*mock_device_proxy(), address())
        .Times(device_call_times)
        .WillRepeatedly(ReturnRef(device_properties->address.value()));
    EXPECT_CALL(*mock_device_proxy(), is_name_valid())
        .Times(device_call_times)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_device_proxy(), name())
        .Times(device_call_times)
        .WillRepeatedly(ReturnRef(device_properties->name.value()));
    EXPECT_CALL(*mock_device_proxy(), is_type_valid())
        .Times(device_call_times)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_device_proxy(), type())
        .Times(device_call_times)
        .WillRepeatedly(ReturnRef(device_properties->type.value()));
    EXPECT_CALL(*mock_device_proxy(), is_appearance_valid())
        .Times(device_call_times)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_device_proxy(), appearance())
        .Times(device_call_times)
        .WillRepeatedly(Return(device_properties->appearance.value()));
    EXPECT_CALL(*mock_device_proxy(), is_modalias_valid())
        .Times(device_call_times)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_device_proxy(), modalias())
        .Times(device_call_times)
        .WillRepeatedly(ReturnRef(device_properties->modalias.value()));
    EXPECT_CALL(*mock_device_proxy(), is_rssi_valid())
        .Times(device_call_times)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_device_proxy(), rssi())
        .Times(device_call_times)
        .WillRepeatedly(Return(device_properties->rssi.value()));
    EXPECT_CALL(*mock_device_proxy(), is_mtu_valid())
        .Times(device_call_times)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_device_proxy(), mtu())
        .Times(device_call_times)
        .WillRepeatedly(Return(device_properties->mtu.value()));
    EXPECT_CALL(*mock_device_proxy(), is_uuids_valid())
        .Times(device_call_times)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_device_proxy(), uuids())
        .Times(device_call_times)
        .WillRepeatedly(ReturnRef(device_properties->uuids.value()));
    EXPECT_CALL(*mock_device_proxy(), is_bluetooth_class_valid())
        .Times(device_call_times)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_device_proxy(), bluetooth_class())
        .Times(device_call_times)
        .WillRepeatedly(Return(device_properties->bluetooth_class.value()));
    EXPECT_CALL(*mock_device_proxy(), adapter())
        .Times(device_call_times)
        .WillRepeatedly(ReturnRef(adapter_path()));
    EXPECT_CALL(*mock_device_proxy(), GetObjectPath())
        .Times(device_call_times)
        .WillRepeatedly(ReturnRef(device_path()));
  }
  void SetMockDeviceProxyCallWithInvalidProperties(
      const std::unique_ptr<org::bluez::Device1Proxy::PropertySet>&
          device_properties) {
    EXPECT_CALL(*mock_device_proxy(), connected())
        .WillOnce(Return(device_properties->connected.value()));
    EXPECT_CALL(*mock_device_proxy(), address())
        .WillOnce(ReturnRef(device_properties->address.value()));
    EXPECT_CALL(*mock_device_proxy(), is_name_valid()).WillOnce(Return(false));
    EXPECT_CALL(*mock_device_proxy(), is_type_valid()).WillOnce(Return(false));
    EXPECT_CALL(*mock_device_proxy(), is_appearance_valid())
        .WillOnce(Return(false));
    EXPECT_CALL(*mock_device_proxy(), is_modalias_valid())
        .WillOnce(Return(false));
    EXPECT_CALL(*mock_device_proxy(), is_rssi_valid()).WillOnce(Return(false));
    EXPECT_CALL(*mock_device_proxy(), is_mtu_valid()).WillOnce(Return(false));
    EXPECT_CALL(*mock_device_proxy(), is_uuids_valid()).WillOnce(Return(false));
    EXPECT_CALL(*mock_device_proxy(), is_bluetooth_class_valid())
        .WillOnce(Return(false));
    EXPECT_CALL(*mock_device_proxy(), adapter())
        .WillOnce(ReturnRef(adapter_path()));
    EXPECT_CALL(*mock_device_proxy(), GetObjectPath())
        .WillOnce(ReturnRef(device_path()));
  }
  void SetMockOtherProxyCall(
      const std::unique_ptr<org::bluez::AdminPolicyStatus1Proxy::PropertySet>&
          admin_policy_properties,
      const std::unique_ptr<
          org::bluez::LEAdvertisingManager1Proxy::PropertySet>&
          advertising_properties,
      const std::unique_ptr<org::bluez::Battery1Proxy::PropertySet>&
          battery_properties) {
    // Admin Policy proxy.
    EXPECT_CALL(*mock_admin_policy_proxy(), GetObjectPath())
        .WillOnce(ReturnRef(adapter_path()));
    EXPECT_CALL(*mock_admin_policy_proxy(), service_allow_list())
        .WillOnce(
            ReturnRef(admin_policy_properties->service_allow_list.value()));
    // Advertising proxy.
    EXPECT_CALL(*mock_advertising_proxy(), GetObjectPath())
        .WillOnce(ReturnRef(adapter_path()));
    EXPECT_CALL(*mock_advertising_proxy(), supported_capabilities())
        .WillOnce(
            ReturnRef(advertising_properties->supported_capabilities.value()));
    // Battery proxy.
    EXPECT_CALL(*mock_battery_proxy(), GetObjectPath())
        .WillOnce(ReturnRef(device_path()));
    EXPECT_CALL(*mock_battery_proxy(), percentage())
        .WillOnce(Return(battery_properties->percentage.value()));
  }

 private:
  MockContext mock_context_;
  // Mock proxy.
  std::unique_ptr<org::bluez::Adapter1ProxyMock> adapter_proxy_ =
      std::make_unique<StrictMock<org::bluez::Adapter1ProxyMock>>();
  std::unique_ptr<org::bluez::Device1ProxyMock> device_proxy_ =
      std::make_unique<StrictMock<org::bluez::Device1ProxyMock>>();
  std::unique_ptr<org::bluez::AdminPolicyStatus1ProxyMock> admin_policy_proxy_ =
      std::make_unique<StrictMock<org::bluez::AdminPolicyStatus1ProxyMock>>();
  std::unique_ptr<org::bluez::LEAdvertisingManager1ProxyMock>
      advertising_proxy_ = std::make_unique<
          StrictMock<org::bluez::LEAdvertisingManager1ProxyMock>>();
  std::unique_ptr<org::bluez::Battery1ProxyMock> battery_proxy_ =
      std::make_unique<StrictMock<org::bluez::Battery1ProxyMock>>();
  // Mock object path for Bluetooth adapter and device.
  const dbus::ObjectPath adapter_path_ = dbus::ObjectPath("/org/bluez/hci0");
  const dbus::ObjectPath device_path_ =
      dbus::ObjectPath("/org/bluez/dev_70_88_6B_92_34_70");
};

// Test that Bluetooth info can be fetched successfully.
TEST_F(BluetoothFetcherTest, FetchBluetoothInfo) {
  // Get mock data.
  const auto adapter_properties = GetAdapterProperties();
  const auto device_properties = GetDeviceProperties();
  const auto admin_policy_properties = GetAdapterPolicyProperties();
  const auto advertising_properties = GetAdapterAdvertisingProperties();
  const auto battery_properties = GetDeviceBatteryProperties();
  SetMockAdapterProxyCall(adapter_properties);
  SetMockDeviceProxyCall(device_properties, 1);
  SetMockOtherProxyCall(admin_policy_properties, advertising_properties,
                        battery_properties);

  EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
      .WillOnce(Return(std::vector<org::bluez::Adapter1ProxyInterface*>{
          mock_adapter_proxy()}));
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetDevices())
      .WillOnce(Return(std::vector<org::bluez::Device1ProxyInterface*>{
          mock_device_proxy()}));
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdminPolicies())
      .WillOnce(
          Return(std::vector<org::bluez::AdminPolicyStatus1ProxyInterface*>{
              mock_admin_policy_proxy()}));
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdvertisings())
      .WillOnce(
          Return(std::vector<org::bluez::LEAdvertisingManager1ProxyInterface*>{
              mock_advertising_proxy()}));
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetBatteries())
      .WillOnce(Return(std::vector<org::bluez::Battery1ProxyInterface*>{
          mock_battery_proxy()}));
  auto bluetooth_result = FetchBluetoothInfo(mock_context());

  // Evaluate whether the information is correct or not.
  ASSERT_TRUE(bluetooth_result->is_bluetooth_adapter_info());
  const auto& adapter_info = bluetooth_result->get_bluetooth_adapter_info();
  ASSERT_EQ(adapter_info.size(), 1);
  EXPECT_EQ(adapter_info[0]->name, adapter_properties->name.value());
  EXPECT_EQ(adapter_info[0]->address, adapter_properties->address.value());
  EXPECT_TRUE(adapter_info[0]->powered);
  EXPECT_EQ(adapter_info[0]->num_connected_devices, 1);
  ASSERT_TRUE(adapter_info[0]->connected_devices.has_value());
  EXPECT_EQ(adapter_info[0]->connected_devices.value().size(), 1);
  EXPECT_EQ(adapter_info[0]->discoverable,
            adapter_properties->discoverable.value());
  EXPECT_EQ(adapter_info[0]->discovering,
            adapter_properties->discovering.value());
  ASSERT_TRUE(adapter_info[0]->uuids.has_value());
  EXPECT_EQ(adapter_info[0]->uuids, adapter_properties->uuids.value());
  ASSERT_TRUE(adapter_info[0]->modalias.has_value());
  EXPECT_EQ(adapter_info[0]->modalias, adapter_properties->modalias.value());
  EXPECT_EQ(adapter_info[0]->service_allow_list,
            admin_policy_properties->service_allow_list.value());

  const brillo::VariantDictionary adapter_capabilities_info = {
      {"MaxAdvLen", adapter_info[0]->supported_capabilities->max_adv_len},
      {"MaxScnRspLen",
       adapter_info[0]->supported_capabilities->max_scn_rsp_len},
      {"MinTxPower", adapter_info[0]->supported_capabilities->min_tx_power},
      {"MaxTxPower", adapter_info[0]->supported_capabilities->max_tx_power}};
  EXPECT_EQ(adapter_capabilities_info,
            advertising_properties->supported_capabilities.value());

  const auto& device_info = adapter_info[0]->connected_devices.value()[0];
  EXPECT_EQ(device_info->address, device_properties->address.value());
  EXPECT_EQ(device_info->name, device_properties->name.value());
  EXPECT_EQ(ConvertDeviceType(device_info->type),
            device_properties->type.value());
  EXPECT_EQ(device_info->appearance->value,
            device_properties->appearance.value());
  EXPECT_EQ(device_info->modalias, device_properties->modalias.value());
  EXPECT_EQ(device_info->rssi->value, device_properties->rssi.value());
  EXPECT_EQ(device_info->mtu->value, device_properties->mtu.value());
  EXPECT_EQ(device_info->uuids, device_properties->uuids.value());
  EXPECT_EQ(device_info->bluetooth_class->value,
            device_properties->bluetooth_class.value());
  EXPECT_EQ(device_info->battery_percentage->value,
            battery_properties->percentage.value());
}

// Test that getting no adapter and device objects is handled gracefully.
TEST_F(BluetoothFetcherTest, NoObjects) {
  auto bluetooth_result = FetchBluetoothInfo(mock_context());
  ASSERT_TRUE(bluetooth_result->is_bluetooth_adapter_info());
  const auto& adapter_info = bluetooth_result->get_bluetooth_adapter_info();
  EXPECT_EQ(adapter_info.size(), 0);
}

// Test that the number of connected devices is counted correctly.
TEST_F(BluetoothFetcherTest, NumConnectedDevices) {
  const auto adapter_properties = GetAdapterProperties();
  const auto device_properties = GetDeviceProperties();
  SetMockAdapterProxyCall(adapter_properties);
  SetMockDeviceProxyCall(device_properties, 2);

  EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
      .WillOnce(Return(std::vector<org::bluez::Adapter1ProxyInterface*>{
          mock_adapter_proxy()}));
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetDevices())
      .WillOnce(Return(std::vector<org::bluez::Device1ProxyInterface*>{
          mock_device_proxy(), mock_device_proxy()}));
  auto bluetooth_result = FetchBluetoothInfo(mock_context());
  ASSERT_TRUE(bluetooth_result->is_bluetooth_adapter_info());
  const auto& adapter_info = bluetooth_result->get_bluetooth_adapter_info();
  ASSERT_EQ(adapter_info.size(), 1);
  EXPECT_EQ(adapter_info[0]->num_connected_devices, 2);
  ASSERT_TRUE(adapter_info[0]->connected_devices.has_value());
  EXPECT_EQ(adapter_info[0]->connected_devices.value().size(), 2);
}

// Test that a disconnected device is not counted as a connected device.
TEST_F(BluetoothFetcherTest, DisconnectedDevice) {
  const auto adapter_properties = GetAdapterProperties();
  const auto device_properties = GetDeviceProperties();
  SetMockAdapterProxyCall(adapter_properties);
  // Set as disconnected device.
  EXPECT_CALL(*mock_device_proxy(), connected()).WillOnce(Return(false));

  EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
      .WillOnce(Return(std::vector<org::bluez::Adapter1ProxyInterface*>{
          mock_adapter_proxy()}));
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetDevices())
      .WillOnce(Return(std::vector<org::bluez::Device1ProxyInterface*>{
          mock_device_proxy()}));
  auto bluetooth_result = FetchBluetoothInfo(mock_context());
  ASSERT_TRUE(bluetooth_result->is_bluetooth_adapter_info());
  const auto& adapter_info = bluetooth_result->get_bluetooth_adapter_info();
  ASSERT_EQ(adapter_info.size(), 1);
  EXPECT_EQ(adapter_info[0]->num_connected_devices, 0);
  ASSERT_FALSE(adapter_info[0]->connected_devices.has_value());
}

// Test that a disconnected device is not counted as a connected device.
TEST_F(BluetoothFetcherTest, DeviceWithInvalidProperties) {
  const auto adapter_properties = GetAdapterProperties();
  const auto device_properties = GetDeviceProperties();
  SetMockAdapterProxyCall(adapter_properties);
  SetMockDeviceProxyCallWithInvalidProperties(device_properties);

  EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
      .WillOnce(Return(std::vector<org::bluez::Adapter1ProxyInterface*>{
          mock_adapter_proxy()}));
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetDevices())
      .WillOnce(Return(std::vector<org::bluez::Device1ProxyInterface*>{
          mock_device_proxy()}));
  auto bluetooth_result = FetchBluetoothInfo(mock_context());
  ASSERT_TRUE(bluetooth_result->is_bluetooth_adapter_info());
  const auto& adapter_info = bluetooth_result->get_bluetooth_adapter_info();
  ASSERT_EQ(adapter_info.size(), 1);
  EXPECT_EQ(adapter_info[0]->num_connected_devices, 1);
  ASSERT_TRUE(adapter_info[0]->connected_devices.has_value());
  EXPECT_EQ(adapter_info[0]->connected_devices.value().size(), 1);

  const auto& device_info = adapter_info[0]->connected_devices.value()[0];
  EXPECT_EQ(device_info->address, device_properties->address.value());
  EXPECT_FALSE(device_info->name.has_value());
  EXPECT_EQ(device_info->type, mojom::BluetoothDeviceType::kUnfound);
  EXPECT_FALSE(device_info->appearance);
  EXPECT_FALSE(device_info->modalias.has_value());
  EXPECT_FALSE(device_info->rssi);
  EXPECT_FALSE(device_info->mtu);
  EXPECT_FALSE(device_info->uuids.has_value());
  EXPECT_FALSE(device_info->battery_percentage);
  EXPECT_FALSE(device_info->bluetooth_class);
}

}  // namespace
}  // namespace diagnostics
