// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/telemetry/bluetooth_event_service_impl.h"

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <dbus/object_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/wilco_dtc_supportd/telemetry/bluetooth_event_service.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/bluetooth_client.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/fake_bluetooth_client.h"

using ::testing::_;
using ::testing::ElementsAreArray;
using ::testing::Eq;
using ::testing::Invoke;
using ::testing::SaveArg;
using ::testing::StrictMock;

namespace diagnostics {
namespace wilco {
namespace {

using AdapterData = BluetoothEventService::AdapterData;

constexpr char kAdapterName1[] = "hci0";
constexpr char kAdapterName2[] = "hci1";
constexpr char kAdapterMac1[] = "aa:bb:cc:dd:ee:ff";
constexpr char kAdapterMac2[] = "00:11:22:33:44:55";

const dbus::ObjectPath kAdapterPath1("/org/bluez/hci0");
const dbus::ObjectPath kAdapterPath2("/org/bluez/hci1");
const dbus::ObjectPath kDevicePath1("/org/bluez/hci0/dev_70_88_6B_92_34_70");
const dbus::ObjectPath kDevicePath2("/org/bluez/hci0/dev_92_34_70_70_88_6B");
const dbus::ObjectPath kDevicePath3("/org/bluez/hci0/dev_70_70_88_6B_92_34");

void PropertyChanged(const std::string& property_name) {}

std::unique_ptr<BluetoothClient::AdapterProperties> CreateAdapterProperties(
    const std::string& name, const std::string& address, bool powered) {
  auto properties = std::make_unique<BluetoothClient::AdapterProperties>(
      nullptr, base::BindRepeating(&PropertyChanged));
  properties->name.ReplaceValue(name);
  properties->address.ReplaceValue(address);
  properties->powered.ReplaceValue(powered);
  return properties;
}

std::unique_ptr<BluetoothClient::DeviceProperties> CreateDeviceProperties(
    bool connected, const dbus::ObjectPath& adapter_path) {
  auto properties = std::make_unique<BluetoothClient::DeviceProperties>(
      nullptr, base::BindRepeating(&PropertyChanged));
  properties->name.ReplaceValue("keyboard");
  properties->address.ReplaceValue("70:88:6B:92:34:70");
  properties->connected.ReplaceValue(connected);
  properties->adapter.ReplaceValue(adapter_path);
  return properties;
}

AdapterData CreateAdapterData(const std::string& name,
                              const std::string& address,
                              bool powered,
                              uint32_t connected_devices_count) {
  AdapterData adapter;
  adapter.name = name;
  adapter.address = address;
  adapter.powered = powered;
  adapter.connected_devices_count = connected_devices_count;
  return adapter;
}

class MockBluetoothEventServiceObserver
    : public BluetoothEventService::Observer {
 public:
  MOCK_METHOD(void,
              BluetoothAdapterDataChanged,
              (const std::vector<AdapterData>&),
              (override));
};

class BluetoothEventServiceImplTest : public ::testing::Test {
 public:
  BluetoothEventServiceImplTest()
      : bluetooth_service_(
            new BluetoothEventServiceImpl(&fake_bluetooth_client_)) {
    bluetooth_service_->AddObserver(&observer_);
  }
  BluetoothEventServiceImplTest(const BluetoothEventServiceImplTest&) = delete;
  BluetoothEventServiceImplTest& operator=(
      const BluetoothEventServiceImplTest&) = delete;

  ~BluetoothEventServiceImplTest() override {
    bluetooth_service_->RemoveObserver(&observer_);

    BluetoothClient::Observer* bluetooth_client_observer =
        bluetooth_service_.get();
    bluetooth_service_.reset();
    EXPECT_FALSE(fake_bluetooth_client_.HasObserver(bluetooth_client_observer));
  }

  void SetUp() override {
    ASSERT_TRUE(fake_bluetooth_client_.HasObserver(bluetooth_service_.get()));
  }

  void ExpectBluetoothDataChanged(
      const std::vector<AdapterData>& adapters_data) {
    EXPECT_CALL(observer_,
                BluetoothAdapterDataChanged(ElementsAreArray(adapters_data)))
        .WillOnce(Invoke([&](const std::vector<AdapterData>& arg) {
          EXPECT_EQ(bluetooth_service_->GetLatestEvent(), arg);
        }));
  }

 protected:
  FakeBluetoothClient fake_bluetooth_client_;
  std::unique_ptr<BluetoothEventServiceImpl> bluetooth_service_;

  StrictMock<MockBluetoothEventServiceObserver> observer_;
};

TEST_F(BluetoothEventServiceImplTest, AdapterAdded) {
  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));
}

TEST_F(BluetoothEventServiceImplTest, MultipleAdaptersAdded) {
  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));

  // Should not invoke BluetoothAdapterDataChanged.
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName2, kAdapterMac2, false /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName2, kAdapterMac2,
                                              false /* powered */));
}

TEST_F(BluetoothEventServiceImplTest, AdapterRemoved) {
  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));

  ExpectBluetoothDataChanged({});
  fake_bluetooth_client_.EmitAdapterRemoved(kAdapterPath1);

  // Should not invoke BluetoothAdapterDataChanged.
  fake_bluetooth_client_.EmitAdapterRemoved(kAdapterPath1);
}

TEST_F(BluetoothEventServiceImplTest, AdapterRemovedBeforeAdded) {
  // Should not invoke BluetoothAdapterDataChanged.
  fake_bluetooth_client_.EmitAdapterRemoved(kAdapterPath1);
  fake_bluetooth_client_.EmitAdapterRemoved(kAdapterPath2);

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));
}

TEST_F(BluetoothEventServiceImplTest, AdapterPropertyChanged) {
  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, false /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterPropertyChanged(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              false /* powered */));

  // Should not invoke BluetoothAdapterDataChanged.
  fake_bluetooth_client_.EmitAdapterPropertyChanged(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              false /* powered */));
}

TEST_F(BluetoothEventServiceImplTest, AdapterPropertyChangedBeforeAdded) {
  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterPropertyChanged(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName2, kAdapterMac2, false /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName2, kAdapterMac2,
                                              false /* powered */));
}

TEST_F(BluetoothEventServiceImplTest, DeviceAdded) {
  // Should not invoke BluetoothAdapterDataChanged.
  fake_bluetooth_client_.EmitDeviceAdded(
      kDevicePath1,
      *CreateDeviceProperties(true /* connected */, kAdapterPath1));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         1 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));

  // Should not invoke BluetoothAdapterDataChanged.
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));
}

TEST_F(BluetoothEventServiceImplTest, NonConnectedDeviceAdded) {
  // Should not invoke BluetoothAdapterDataChanged.
  fake_bluetooth_client_.EmitDeviceAdded(
      kDevicePath1,
      *CreateDeviceProperties(false /* connected */, kAdapterPath1));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));
}

TEST_F(BluetoothEventServiceImplTest, DeviceRemoved) {
  // Should not invoke BluetoothAdapterDataChanged.
  fake_bluetooth_client_.EmitDeviceAdded(
      kDevicePath1,
      *CreateDeviceProperties(true /* connected */, kAdapterPath1));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         1 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitDeviceRemoved(kDevicePath1);

  // Should not invoke BluetoothAdapterDataChanged.
  fake_bluetooth_client_.EmitDeviceRemoved(kDevicePath1);
}

TEST_F(BluetoothEventServiceImplTest, DeviceRemovedBeforeAdded) {
  // Should not invoke BluetoothAdapterDataChanged.
  fake_bluetooth_client_.EmitDeviceRemoved(kDevicePath1);
  fake_bluetooth_client_.EmitDeviceRemoved(kDevicePath2);

  fake_bluetooth_client_.EmitDeviceAdded(
      kDevicePath1,
      *CreateDeviceProperties(true /* connected */, kAdapterPath1));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         1 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));
}

TEST_F(BluetoothEventServiceImplTest, DeviceAddedAndRemovedBeingHomeless) {
  // Should not invoke BluetoothAdapterDataChanged.
  fake_bluetooth_client_.EmitDeviceAdded(
      kDevicePath1,
      *CreateDeviceProperties(true /* connected */, kAdapterPath1));
  fake_bluetooth_client_.EmitDeviceRemoved(kDevicePath1);

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));
}

TEST_F(BluetoothEventServiceImplTest, DevicePropertyChanged) {
  // Should not invoke BluetoothAdapterDataChanged.
  fake_bluetooth_client_.EmitDeviceAdded(
      kDevicePath1,
      *CreateDeviceProperties(true /* connected */, kAdapterPath1));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         1 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitDevicePropertyChanged(
      kDevicePath1,
      *CreateDeviceProperties(false /* connected */, kAdapterPath1));

  // Should not invoke BluetoothAdapterDataChanged.
  fake_bluetooth_client_.EmitDevicePropertyChanged(
      kDevicePath1,
      *CreateDeviceProperties(false /* connected */, kAdapterPath1));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         1 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitDevicePropertyChanged(
      kDevicePath1,
      *CreateDeviceProperties(true /* connected */, kAdapterPath1));

  // Should not invoke BluetoothAdapterDataChanged.
  fake_bluetooth_client_.EmitDevicePropertyChanged(
      kDevicePath1,
      *CreateDeviceProperties(true /* connected */, kAdapterPath1));
}

TEST_F(BluetoothEventServiceImplTest, DevicePropertyChangedBeforeAdded) {
  // Should not invoke BluetoothAdapterDataChanged.
  fake_bluetooth_client_.EmitDevicePropertyChanged(
      kDevicePath1,
      *CreateDeviceProperties(true /* connected */, kAdapterPath1));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         1 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitDevicePropertyChanged(
      kDevicePath1,
      *CreateDeviceProperties(false /* connected */, kAdapterPath1));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         1 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitDeviceAdded(
      kDevicePath1,
      *CreateDeviceProperties(true /* connected */, kAdapterPath1));
}

TEST_F(BluetoothEventServiceImplTest, MultipleAdaptersAndDevices) {
  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         0 /* connected_devices_count */),
       CreateAdapterData(kAdapterName2, kAdapterMac2, true /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath2, *CreateAdapterProperties(kAdapterName2, kAdapterMac2,
                                              true /* powered */));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         1 /* connected_devices_count */),
       CreateAdapterData(kAdapterName2, kAdapterMac2, true /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitDevicePropertyChanged(
      kDevicePath1,
      *CreateDeviceProperties(true /* connected */, kAdapterPath1));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         2 /* connected_devices_count */),
       CreateAdapterData(kAdapterName2, kAdapterMac2, true /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitDevicePropertyChanged(
      kDevicePath2,
      *CreateDeviceProperties(true /* connected */, kAdapterPath1));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         2 /* connected_devices_count */),
       CreateAdapterData(kAdapterName2, kAdapterMac2, true /* powered */,
                         1 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitDevicePropertyChanged(
      kDevicePath3,
      *CreateDeviceProperties(true /* connected */, kAdapterPath2));
}

TEST_F(BluetoothEventServiceImplTest, RemoveAdapterWithConnectedDevice) {
  // Should not invoke BluetoothAdapterDataChanged.
  fake_bluetooth_client_.EmitDeviceAdded(
      kDevicePath1,
      *CreateDeviceProperties(true /* connected */, kAdapterPath1));

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         1 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));

  ExpectBluetoothDataChanged({});
  fake_bluetooth_client_.EmitAdapterRemoved(kAdapterPath1);

  ExpectBluetoothDataChanged(
      {CreateAdapterData(kAdapterName1, kAdapterMac1, true /* powered */,
                         0 /* connected_devices_count */)});
  fake_bluetooth_client_.EmitAdapterAdded(
      kAdapterPath1, *CreateAdapterProperties(kAdapterName1, kAdapterMac1,
                                              true /* powered */));
}

}  // namespace
}  // namespace wilco
}  // namespace diagnostics
