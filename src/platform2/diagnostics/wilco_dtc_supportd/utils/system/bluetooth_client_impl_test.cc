// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <vector>

#include <base/functional/bind.h>
#include <base/memory/ref_counted.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_runner.h>
#include <base/test/task_environment.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_manager.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/bluetooth/dbus-constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/wilco_dtc_supportd/utils/system/bluetooth_client.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/bluetooth_client_impl.h"

using ::testing::_;
using ::testing::ElementsAreArray;
using ::testing::Mock;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::StrictMock;

namespace diagnostics {
namespace wilco {
namespace {

const dbus::ObjectPath kAdapterPath("/org/bluez/hci0");
const dbus::ObjectPath kDevicePath("/org/bluez/hci0/dev_70_88_6B_92_34_70");

void PropertyChanged(const std::string& property_name) {}

std::unique_ptr<BluetoothClient::AdapterProperties> GetAdapterProperties() {
  auto properties = std::make_unique<BluetoothClient::AdapterProperties>(
      nullptr, base::BindRepeating(&PropertyChanged));
  properties->address.ReplaceValue("aa:bb:cc:dd:ee:ff");
  properties->name.ReplaceValue("sarien-laptop");
  properties->powered.ReplaceValue(true);
  properties->address.set_valid(true);
  properties->name.set_valid(true);
  properties->powered.set_valid(true);
  return properties;
}

std::unique_ptr<BluetoothClient::DeviceProperties> GetDeviceProperties() {
  auto properties = std::make_unique<BluetoothClient::DeviceProperties>(
      nullptr, base::BindRepeating(&PropertyChanged));
  properties->address.ReplaceValue("70:88:6B:92:34:70");
  properties->name.ReplaceValue("GID6B");
  properties->connected.ReplaceValue(true);
  properties->address.set_valid(true);
  properties->name.set_valid(true);
  properties->connected.set_valid(true);
  return properties;
}

MATCHER_P(AdapterPropertiesEquals, expected_properties, "") {
  return arg.address.value() == expected_properties->address.value() &&
         arg.name.value() == expected_properties->name.value() &&
         arg.powered.value() == expected_properties->powered.value();
}

MATCHER_P(DevicePropertiesEquals, expected_properties, "") {
  return arg.address.value() == expected_properties->address.value() &&
         arg.name.value() == expected_properties->name.value() &&
         arg.connected.value() == expected_properties->connected.value();
}

class MockBluetoothClientObserver : public BluetoothClient::Observer {
 public:
  MOCK_METHOD(void,
              AdapterAdded,
              (const dbus::ObjectPath& object_path,
               const BluetoothClient::AdapterProperties& properties));
  MOCK_METHOD(void, AdapterRemoved, (const dbus::ObjectPath& object_path));
  MOCK_METHOD(void,
              AdapterPropertyChanged,
              (const dbus::ObjectPath& object_path,
               const BluetoothClient::AdapterProperties& properties));
  MOCK_METHOD(void,
              DeviceAdded,
              (const dbus::ObjectPath& object_path,
               const BluetoothClient::DeviceProperties& properties));
  MOCK_METHOD(void, DeviceRemoved, (const dbus::ObjectPath& object_path));
  MOCK_METHOD(void,
              DevicePropertyChanged,
              (const dbus::ObjectPath& object_path,
               const BluetoothClient::DeviceProperties& properties));
};

class BluetoothClientImplTest : public ::testing::Test {
 public:
  BluetoothClientImplTest()
      : dbus_bus_(new dbus::MockBus(dbus::Bus::Options())),
        dbus_object_proxy_(new dbus::MockObjectProxy(
            dbus_bus_.get(),
            bluez_object_manager::kBluezObjectManagerServiceName,
            dbus::ObjectPath(
                bluez_object_manager::kBluezObjectManagerServicePath))) {}
  BluetoothClientImplTest(const BluetoothClientImplTest&) = delete;
  BluetoothClientImplTest& operator=(const BluetoothClientImplTest&) = delete;
  ~BluetoothClientImplTest() override {
    EXPECT_CALL(
        *dbus_object_manager_,
        UnregisterInterface(bluetooth_adapter::kBluetoothAdapterInterface));
    EXPECT_CALL(
        *dbus_object_manager_,
        UnregisterInterface(bluetooth_device::kBluetoothDeviceInterface));
  }

  void SetUp() override {
    ON_CALL(*dbus_bus_, GetDBusTaskRunner())
        .WillByDefault(
            Return(base::SingleThreadTaskRunner::GetCurrentDefault().get()));

    EXPECT_CALL(*dbus_bus_,
                GetObjectProxy(
                    bluez_object_manager::kBluezObjectManagerServiceName,
                    dbus::ObjectPath(
                        bluez_object_manager::kBluezObjectManagerServicePath)))
        .WillOnce(Return(dbus_object_proxy_.get()));

    dbus_object_manager_ = new StrictMock<dbus::MockObjectManager>(
        dbus_bus_.get(), bluez_object_manager::kBluezObjectManagerServiceName,
        dbus::ObjectPath(bluez_object_manager::kBluezObjectManagerServicePath));

    // Force TaskRunner to run pending tasks as effect of instantiating
    // MockObjectManager. Needed to avoid memory leaks because pending tasks
    // are unowned pointers that will only self destruct after being run.
    base::RunLoop run_loop;
    run_loop.RunUntilIdle();

    EXPECT_CALL(*dbus_bus_,
                GetObjectManager(
                    bluez_object_manager::kBluezObjectManagerServiceName,
                    dbus::ObjectPath(
                        bluez_object_manager::kBluezObjectManagerServicePath)))
        .WillOnce(Return(dbus_object_manager_.get()));

    EXPECT_CALL(*dbus_object_manager_,
                RegisterInterface(bluetooth_adapter::kBluetoothAdapterInterface,
                                  NotNull()))
        .WillOnce(SaveArg<1>(&adapter_manager_interface_));
    EXPECT_CALL(*dbus_object_manager_,
                RegisterInterface(bluetooth_device::kBluetoothDeviceInterface,
                                  NotNull()))
        .WillOnce(SaveArg<1>(&device_manager_interface_));

    bluetooth_client_ = std::make_unique<BluetoothClientImpl>(dbus_bus_);

    ASSERT_TRUE(Mock::VerifyAndClearExpectations(dbus_bus_.get()));
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(dbus_object_manager_.get()));

    bluetooth_client_->AddObserver(&observer_);
  }

  MockBluetoothClientObserver* observer() { return &observer_; }

  dbus::MockObjectManager* object_manager() {
    return dbus_object_manager_.get();
  }

  dbus::ObjectManager::Interface* adapter_manager_interface() {
    return adapter_manager_interface_;
  }

  dbus::ObjectManager::Interface* device_manager_interface() {
    return device_manager_interface_;
  }

  BluetoothClient* bluetooth_client() const { return bluetooth_client_.get(); }

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};

  StrictMock<MockBluetoothClientObserver> observer_;

  scoped_refptr<dbus::MockBus> dbus_bus_;
  scoped_refptr<dbus::MockObjectProxy> dbus_object_proxy_;
  scoped_refptr<StrictMock<dbus::MockObjectManager>> dbus_object_manager_;

  std::unique_ptr<BluetoothClientImpl> bluetooth_client_;

  // Not owned. Pointers passed by |bluetooth_client_| to
  // |dbus_object_manager_|.
  dbus::ObjectManager::Interface* adapter_manager_interface_;
  dbus::ObjectManager::Interface* device_manager_interface_;
};

TEST_F(BluetoothClientImplTest, GetAdapters) {
  const std::vector<dbus::ObjectPath> kAdapterPaths = {kAdapterPath};
  EXPECT_CALL(
      *object_manager(),
      GetObjectsWithInterface(bluetooth_adapter::kBluetoothAdapterInterface))
      .WillOnce(Return(kAdapterPaths));

  std::vector<dbus::ObjectPath> adapter_paths =
      bluetooth_client()->GetAdapters();
  EXPECT_THAT(adapter_paths, ElementsAreArray(kAdapterPaths));
}

TEST_F(BluetoothClientImplTest, GetDevices) {
  const std::vector<dbus::ObjectPath> kDevicePaths = {kDevicePath};
  EXPECT_CALL(
      *object_manager(),
      GetObjectsWithInterface(bluetooth_device::kBluetoothDeviceInterface))
      .WillOnce(Return(kDevicePaths));

  std::vector<dbus::ObjectPath> device_paths = bluetooth_client()->GetDevices();
  EXPECT_THAT(device_paths, ElementsAreArray(kDevicePaths));
}

TEST_F(BluetoothClientImplTest, GetAdapterProperties) {
  const auto kProperties = GetAdapterProperties();
  EXPECT_CALL(*object_manager(),
              GetProperties(kAdapterPath,
                            bluetooth_adapter::kBluetoothAdapterInterface))
      .WillOnce(Return(kProperties.get()));

  auto adapter_properties =
      bluetooth_client()->GetAdapterProperties(kAdapterPath);
  ASSERT_TRUE(adapter_properties);
  EXPECT_THAT(*adapter_properties, AdapterPropertiesEquals(kProperties.get()));
}

TEST_F(BluetoothClientImplTest, GetAdapterPropertiesNullProperties) {
  EXPECT_CALL(*object_manager(),
              GetProperties(kAdapterPath,
                            bluetooth_adapter::kBluetoothAdapterInterface))
      .WillOnce(Return(nullptr));

  EXPECT_FALSE(bluetooth_client()->GetAdapterProperties(kAdapterPath));
}

TEST_F(BluetoothClientImplTest, GetAdapterPropertiesInvalidProperties) {
  auto properties = GetAdapterProperties();
  EXPECT_CALL(*object_manager(),
              GetProperties(kAdapterPath,
                            bluetooth_adapter::kBluetoothAdapterInterface))
      .Times(4)
      .WillRepeatedly(Return(properties.get()));

  properties->address.set_valid(false);
  EXPECT_FALSE(bluetooth_client()->GetAdapterProperties(kAdapterPath));
  properties->address.set_valid(true);

  properties->name.set_valid(false);
  EXPECT_FALSE(bluetooth_client()->GetAdapterProperties(kAdapterPath));
  properties->name.set_valid(true);

  properties->powered.set_valid(false);
  EXPECT_FALSE(bluetooth_client()->GetAdapterProperties(kAdapterPath));
  properties->powered.set_valid(true);

  auto adapter_properties =
      bluetooth_client()->GetAdapterProperties(kAdapterPath);
  ASSERT_TRUE(adapter_properties);
  EXPECT_THAT(*adapter_properties, AdapterPropertiesEquals(properties.get()));
}

TEST_F(BluetoothClientImplTest, GetDeviceProperties) {
  const auto kProperties = GetDeviceProperties();
  EXPECT_CALL(
      *object_manager(),
      GetProperties(kDevicePath, bluetooth_device::kBluetoothDeviceInterface))
      .WillOnce(Return(kProperties.get()));

  auto device_properties = bluetooth_client()->GetDeviceProperties(kDevicePath);
  ASSERT_TRUE(device_properties);
  EXPECT_THAT(*device_properties, DevicePropertiesEquals(kProperties.get()));
}

TEST_F(BluetoothClientImplTest, GetDevicePropertiesNullProperties) {
  EXPECT_CALL(
      *object_manager(),
      GetProperties(kDevicePath, bluetooth_device::kBluetoothDeviceInterface))
      .WillOnce(Return(nullptr));

  EXPECT_FALSE(bluetooth_client()->GetDeviceProperties(kDevicePath));
}

TEST_F(BluetoothClientImplTest, GetDevicePropertiesInvalidProperties) {
  auto properties = GetDeviceProperties();
  EXPECT_CALL(
      *object_manager(),
      GetProperties(kDevicePath, bluetooth_device::kBluetoothDeviceInterface))
      .Times(4)
      .WillRepeatedly(Return(properties.get()));

  properties->address.set_valid(false);
  EXPECT_FALSE(bluetooth_client()->GetDeviceProperties(kDevicePath));
  properties->address.set_valid(true);

  properties->name.set_valid(false);
  EXPECT_FALSE(bluetooth_client()->GetDeviceProperties(kDevicePath));
  properties->name.set_valid(true);

  properties->connected.set_valid(false);
  EXPECT_FALSE(bluetooth_client()->GetDeviceProperties(kDevicePath));
  properties->connected.set_valid(true);

  auto device_properties = bluetooth_client()->GetDeviceProperties(kDevicePath);
  ASSERT_TRUE(device_properties);
  EXPECT_THAT(*device_properties, DevicePropertiesEquals(properties.get()));
}

TEST_F(BluetoothClientImplTest, AdapterAddedNullProperties) {
  EXPECT_CALL(*object_manager(), GetProperties(kAdapterPath, _))
      .WillOnce(Return(nullptr));
  adapter_manager_interface()->ObjectAdded(
      kAdapterPath, bluetooth_adapter::kBluetoothAdapterInterface);
}

TEST_F(BluetoothClientImplTest, AdapterAddedWithInvalidProperties) {
  auto adapter_properties = GetAdapterProperties();
  EXPECT_CALL(*object_manager(),
              GetProperties(kAdapterPath,
                            bluetooth_adapter::kBluetoothAdapterInterface))
      .Times(3)
      .WillRepeatedly(Return(adapter_properties.get()));

  adapter_properties->address.set_valid(false);
  adapter_manager_interface()->ObjectAdded(
      kAdapterPath, bluetooth_adapter::kBluetoothAdapterInterface);
  adapter_properties->address.set_valid(true);

  adapter_properties->name.set_valid(false);
  adapter_manager_interface()->ObjectAdded(
      kAdapterPath, bluetooth_adapter::kBluetoothAdapterInterface);
  adapter_properties->name.set_valid(true);

  adapter_properties->powered.set_valid(false);
  adapter_manager_interface()->ObjectAdded(
      kAdapterPath, bluetooth_adapter::kBluetoothAdapterInterface);
  adapter_properties->powered.set_valid(true);
}

TEST_F(BluetoothClientImplTest, AdapterAdded) {
  const auto kProperties = GetAdapterProperties();
  EXPECT_CALL(*object_manager(),
              GetProperties(kAdapterPath,
                            bluetooth_adapter::kBluetoothAdapterInterface))
      .WillOnce(Return(kProperties.get()));
  EXPECT_CALL(
      *observer(),
      AdapterAdded(kAdapterPath, AdapterPropertiesEquals(kProperties.get())));
  adapter_manager_interface()->ObjectAdded(
      kAdapterPath, bluetooth_adapter::kBluetoothAdapterInterface);
}

TEST_F(BluetoothClientImplTest, AdapterRemoved) {
  EXPECT_CALL(*observer(), AdapterRemoved(kAdapterPath));
  adapter_manager_interface()->ObjectRemoved(
      kAdapterPath, bluetooth_adapter::kBluetoothAdapterInterface);
}

TEST_F(BluetoothClientImplTest, AdapterPropertyChangedNullProperties) {
  dbus::PropertySet* properties_base_ptr =
      adapter_manager_interface()->CreateProperties(
          nullptr, kAdapterPath, bluetooth_adapter::kBluetoothAdapterInterface);
  ASSERT_TRUE(properties_base_ptr);

  std::unique_ptr<BluetoothClient::AdapterProperties> properties(
      static_cast<BluetoothClient::AdapterProperties*>(properties_base_ptr));

  EXPECT_CALL(*object_manager(),
              GetProperties(kAdapterPath,
                            bluetooth_adapter::kBluetoothAdapterInterface))
      .WillOnce(Return(nullptr));
  properties->powered.ReplaceValue(true);
}

TEST_F(BluetoothClientImplTest, AdapterPropertyChanged) {
  dbus::PropertySet* properties_base_ptr =
      adapter_manager_interface()->CreateProperties(
          nullptr, kAdapterPath, bluetooth_adapter::kBluetoothAdapterInterface);
  ASSERT_TRUE(properties_base_ptr);

  std::unique_ptr<BluetoothClient::AdapterProperties> properties(
      static_cast<BluetoothClient::AdapterProperties*>(properties_base_ptr));
  properties->address.set_valid(true);
  properties->name.set_valid(true);
  properties->powered.set_valid(true);

  EXPECT_CALL(*object_manager(),
              GetProperties(kAdapterPath,
                            bluetooth_adapter::kBluetoothAdapterInterface))
      .Times(4)
      .WillRepeatedly(Return(properties_base_ptr));

  properties->address.set_valid(false);
  properties->address.ReplaceValue("aa:aa:aa:ff:ff:ff");
  properties->address.set_valid(true);
  Mock::VerifyAndClearExpectations(observer());

  properties->name.set_valid(false);
  properties->name.ReplaceValue("sarien-laptop");
  properties->name.set_valid(true);
  Mock::VerifyAndClearExpectations(observer());

  properties->powered.set_valid(false);
  properties->powered.ReplaceValue(true);
  properties->powered.set_valid(true);
  Mock::VerifyAndClearExpectations(observer());

  EXPECT_CALL(*observer(),
              AdapterPropertyChanged(
                  kAdapterPath, AdapterPropertiesEquals(properties.get())));
  properties->address.ReplaceValue("ff:ff:ff:aa:aa:aa");
}

TEST_F(BluetoothClientImplTest, DeviceAddedNullProperties) {
  EXPECT_CALL(*object_manager(), GetProperties(kDevicePath, _))
      .WillOnce(Return(nullptr));
  device_manager_interface()->ObjectAdded(
      kDevicePath, bluetooth_device::kBluetoothDeviceInterface);
}

TEST_F(BluetoothClientImplTest, DeviceAddedWithInvalidProperties) {
  auto device_properties = GetDeviceProperties();
  EXPECT_CALL(
      *object_manager(),
      GetProperties(kDevicePath, bluetooth_device::kBluetoothDeviceInterface))
      .Times(3)
      .WillRepeatedly(Return(device_properties.get()));

  device_properties->address.set_valid(false);
  device_manager_interface()->ObjectAdded(
      kDevicePath, bluetooth_device::kBluetoothDeviceInterface);
  device_properties->address.set_valid(true);

  device_properties->name.set_valid(false);
  device_manager_interface()->ObjectAdded(
      kDevicePath, bluetooth_device::kBluetoothDeviceInterface);
  device_properties->name.set_valid(true);

  device_properties->connected.set_valid(false);
  device_manager_interface()->ObjectAdded(
      kDevicePath, bluetooth_device::kBluetoothDeviceInterface);
  device_properties->connected.set_valid(true);
}

TEST_F(BluetoothClientImplTest, DeviceAdded) {
  const auto kProperties = GetDeviceProperties();
  EXPECT_CALL(
      *object_manager(),
      GetProperties(kDevicePath, bluetooth_device::kBluetoothDeviceInterface))
      .WillOnce(Return(kProperties.get()));
  EXPECT_CALL(
      *observer(),
      DeviceAdded(kDevicePath, DevicePropertiesEquals(kProperties.get())));
  device_manager_interface()->ObjectAdded(
      kDevicePath, bluetooth_device::kBluetoothDeviceInterface);
}

TEST_F(BluetoothClientImplTest, DeviceRemoved) {
  const auto kProperties = GetDeviceProperties();
  EXPECT_CALL(*observer(), DeviceRemoved(kDevicePath));
  device_manager_interface()->ObjectRemoved(
      kDevicePath, bluetooth_device::kBluetoothDeviceInterface);
}

TEST_F(BluetoothClientImplTest, DevicePropertyChangedNullProperties) {
  dbus::PropertySet* properties_base_ptr =
      device_manager_interface()->CreateProperties(
          nullptr, kDevicePath, bluetooth_device::kBluetoothDeviceInterface);
  ASSERT_TRUE(properties_base_ptr);

  std::unique_ptr<BluetoothClient::DeviceProperties> properties(
      static_cast<BluetoothClient::DeviceProperties*>(properties_base_ptr));

  EXPECT_CALL(
      *object_manager(),
      GetProperties(kDevicePath, bluetooth_device::kBluetoothDeviceInterface))
      .WillOnce(Return(nullptr));
  properties->connected.ReplaceValue(true);
}

TEST_F(BluetoothClientImplTest, DevicePropertyChanged) {
  dbus::PropertySet* properties_base_ptr =
      device_manager_interface()->CreateProperties(
          nullptr, kDevicePath, bluetooth_device::kBluetoothDeviceInterface);
  ASSERT_TRUE(properties_base_ptr);

  std::unique_ptr<BluetoothClient::DeviceProperties> properties(
      static_cast<BluetoothClient::DeviceProperties*>(properties_base_ptr));
  properties->address.set_valid(true);
  properties->name.set_valid(true);
  properties->connected.set_valid(true);

  EXPECT_CALL(
      *object_manager(),
      GetProperties(kDevicePath, bluetooth_device::kBluetoothDeviceInterface))
      .Times(4)
      .WillRepeatedly(Return(properties_base_ptr));

  properties->address.set_valid(false);
  properties->address.ReplaceValue("ff:ff:ff:aa:aa:aa");
  properties->address.set_valid(true);
  Mock::VerifyAndClearExpectations(observer());

  properties->name.set_valid(false);
  properties->name.ReplaceValue("GID6");
  properties->name.set_valid(true);
  Mock::VerifyAndClearExpectations(observer());

  properties->connected.set_valid(false);
  properties->connected.ReplaceValue(true);
  properties->connected.set_valid(true);
  Mock::VerifyAndClearExpectations(observer());

  EXPECT_CALL(*observer(),
              DevicePropertyChanged(kDevicePath,
                                    DevicePropertiesEquals(properties.get())));
  properties->address.ReplaceValue("aa:aa:aa:ff:ff:ff");
}

TEST_F(BluetoothClientImplTest, AddAndRemoveObserver) {
  const auto kProperties = GetAdapterProperties();

  EXPECT_CALL(*object_manager(),
              GetProperties(kAdapterPath,
                            bluetooth_adapter::kBluetoothAdapterInterface))
      .WillOnce(Return(kProperties.get()));
  EXPECT_CALL(
      *observer(),
      AdapterAdded(kAdapterPath, AdapterPropertiesEquals(kProperties.get())));
  adapter_manager_interface()->ObjectAdded(
      kAdapterPath, bluetooth_adapter::kBluetoothAdapterInterface);

  bluetooth_client()->RemoveObserver(observer());
  EXPECT_CALL(*object_manager(),
              GetProperties(kAdapterPath,
                            bluetooth_adapter::kBluetoothAdapterInterface))
      .WillOnce(Return(kProperties.get()));
  adapter_manager_interface()->ObjectAdded(
      kAdapterPath, bluetooth_adapter::kBluetoothAdapterInterface);
}

}  // namespace
}  // namespace wilco
}  // namespace diagnostics
