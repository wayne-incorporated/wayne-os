// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/bluez_battery_provider.h"

#include <string>

#include <chromeos/dbus/service_constants.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_exported_object.h>
#include <dbus/mock_object_manager.h>
#include <dbus/mock_object_proxy.h>
#include <gtest/gtest.h>
#include "power_manager/powerd/testing/test_environment.h"

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Return;
using ::testing::SaveArg;

namespace power_manager::system {

namespace {

constexpr char kBluetoothBatteryProviderPath[] =
    "/org/chromium/PowerManager/battery_provider";

constexpr char kTestAddress[] = "12:34:56:AB:Cd:ef";
constexpr char kTestAddressPath[] = "12_34_56_AB_CD_EF";

}  // namespace

class BluezBatteryProviderTest : public TestEnvironment {
 public:
  BluezBatteryProviderTest() = default;
  BluezBatteryProviderTest(const BluezBatteryProviderTest&) = delete;
  BluezBatteryProviderTest& operator=(const BluezBatteryProviderTest&) = delete;

  ~BluezBatteryProviderTest() override = default;

  void SetUp() override { bus_ = new dbus::MockBus(dbus::Bus::Options()); }

  void TearDown() override {}

  void HandleBatteryExportedSignal(dbus::Signal* signal) {
    EXPECT_EQ(signal->GetInterface(), dbus::kObjectManagerInterface);
    EXPECT_EQ(signal->GetMember(), dbus::kObjectManagerInterfacesAdded);
  }

  void HandleBatteryUnexportedSignal(dbus::Signal* signal) {
    EXPECT_EQ(signal->GetInterface(), dbus::kObjectManagerInterface);
    EXPECT_EQ(signal->GetMember(), dbus::kObjectManagerInterfacesRemoved);
  }

  void HandleBatteryChangedSignal(dbus::Signal* signal) {
    EXPECT_EQ(signal->GetInterface(), dbus::kPropertiesInterface);
    EXPECT_EQ(signal->GetMember(), dbus::kPropertiesChanged);
  }

 protected:
  void TestInit() {
    // Don't worry about threading assertions.
    EXPECT_CALL(*bus_, AssertOnOriginThread()).Times(AnyNumber());
    EXPECT_CALL(*bus_, AssertOnDBusThread()).Times(AnyNumber());

    // The root object of the battery provider is expected to be exported.
    // "/org/chromium/PowerManager/battery_provider"
    exported_root_object_ = base::MakeRefCounted<dbus::MockExportedObject>(
        bus_.get(), dbus::ObjectPath(kBluetoothBatteryProviderPath));
    EXPECT_CALL(*bus_, GetExportedObject(
                           dbus::ObjectPath(kBluetoothBatteryProviderPath)))
        .WillOnce(Return(exported_root_object_.get()));
    EXPECT_CALL(*exported_root_object_, ExportMethod(_, _, _, _))
        .Times(AnyNumber());

    // The root of ObjectManager of BlueZ, expect that we use it.
    object_proxy_ = base::MakeRefCounted<dbus::MockObjectProxy>(
        bus_.get(),
        bluetooth_battery::kBluetoothBatteryProviderManagerServiceName,
        dbus::ObjectPath("/"));
    EXPECT_CALL(*bus_, GetObjectProxy(_, _))
        .WillOnce(Return(object_proxy_.get()));

    // Expect that we monitor the liveness of BlueZ.
    EXPECT_CALL(*object_proxy_, SetNameOwnerChangedCallback(_)).Times(1);

    // Provide a mock ObjectManager.
    object_manager_ = base::MakeRefCounted<dbus::MockObjectManager>(
        bus_.get(),
        bluetooth_battery::kBluetoothBatteryProviderManagerServiceName,
        dbus::ObjectPath("/"));
    EXPECT_CALL(
        *bus_,
        GetObjectManager(
            bluetooth_battery::kBluetoothBatteryProviderManagerServiceName,
            dbus::ObjectPath("/")))
        .WillOnce(Return(object_manager_.get()));

    // Expect that we are listening to "org.bluez.BatteryProviderManager1" from
    // BlueZ.
    EXPECT_CALL(
        *object_manager_,
        RegisterInterface(
            bluetooth_battery::kBluetoothBatteryProviderManagerInterface,
            &bluez_battery_provider_))
        .Times(1);

    // Trigger init.
    bluez_battery_provider_.Init(bus_);
  }

  scoped_refptr<dbus::MockBus> bus_;
  scoped_refptr<dbus::MockExportedObject> exported_root_object_;
  scoped_refptr<dbus::MockObjectManager> object_manager_;
  scoped_refptr<dbus::MockObjectProxy> object_proxy_;

  BluezBatteryProvider bluez_battery_provider_;
};

TEST_F(BluezBatteryProviderTest, BatteryUpdate) {
  TestInit();

  // When a battery is updated, expect that we export it if it's the first time.
  scoped_refptr<dbus::MockExportedObject> exported_battery =
      base::MakeRefCounted<dbus::MockExportedObject>(
          bus_.get(), dbus::ObjectPath(kBluetoothBatteryProviderPath));
  EXPECT_CALL(*bus_, GetExportedObject(dbus::ObjectPath(
                         std::string(kBluetoothBatteryProviderPath) +
                         std::string("/") + std::string(kTestAddressPath))))
      .WillOnce(Return(exported_battery.get()));
  EXPECT_CALL(*exported_root_object_, SendSignal(_))
      .WillOnce(
          Invoke(this, &BluezBatteryProviderTest::HandleBatteryExportedSignal));
  EXPECT_CALL(*exported_battery, ExportMethod(_, _, _, _)).Times(AnyNumber());
  bluez_battery_provider_.UpdateDeviceBattery(kTestAddress, 90);

  // Subsequent updates should update the properties of the already exported
  // object.
  EXPECT_CALL(*exported_battery, SendSignal(_))
      .WillOnce(
          Invoke(this, &BluezBatteryProviderTest::HandleBatteryChangedSignal));
  bluez_battery_provider_.UpdateDeviceBattery(kTestAddress, 80);

  // At Reset(), battery objects should be unexported.
  EXPECT_CALL(*exported_root_object_, SendSignal(_))
      .WillOnce(Invoke(
          this, &BluezBatteryProviderTest::HandleBatteryUnexportedSignal));
  bluez_battery_provider_.Reset();
}

}  // namespace power_manager::system
