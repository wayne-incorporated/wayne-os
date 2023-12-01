// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/peripheral_battery_watcher.h"

#include <string>
#include <sys/resource.h>

#include <base/check.h>
#include <base/compiler_specific.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

#include "power_manager/common/metrics_constants.h"
#include "power_manager/common/metrics_sender.h"
#include "power_manager/common/test_main_loop_runner.h"
#include "power_manager/powerd/system/dbus_wrapper_stub.h"
#include "power_manager/powerd/system/mock_bluez_battery_provider.h"
#include "power_manager/powerd/system/udev_stub.h"
#include "power_manager/powerd/testing/test_environment.h"
#include "power_manager/proto_bindings/peripheral_battery_status.pb.h"

using ::testing::_;
using ::testing::Gt;
using ::testing::Return;
using ::testing::StrictMock;

namespace power_manager::system {

using std::string;

namespace {

// Abort if it an expected battery update hasn't been received after this long.
constexpr base::TimeDelta kUpdateTimeout = base::Seconds(3);

// Shorter update timeout to use when failure is expected.
constexpr base::TimeDelta kShortUpdateTimeout = base::Milliseconds(100);

const char kDeviceModelName[] = "Test HID Mouse";
const char kWacomUevent[] = "HID_UNIQ=aa:aa:aa:aa:aa:aa";

constexpr char kPeripheralBatterySysname[] = "hid-someperipheral-battery";
constexpr char kPeripheralBatterySerialNumber1[] = "31245";
constexpr char kPeripheralBatterySerialNumber2[] = "DG-0123456789ABCDEF";
constexpr char kBluetoothBatterySysname[] = "hid-11:22:33:aa:bb:cc-battery";
constexpr char kWacomBatterySysname[] = "wacom_battery_1";
constexpr char kNonPeripheralBatterySysname[] = "AC";
constexpr char kPeripheralChargerBatterySysname[] = "peripheral0";
// TODO(b/215381232): Temporarily support both 'PCHG' name and 'peripheral' name
// till upstream kernel driver is merged.
constexpr char kPeripheralChargerBatteryPCHGSysname[] = "PCHG0";

int GetNumberOfOpenFiles() {
  std::string status;
  CHECK(base::ReadFileToString(base::FilePath("/proc/self/status"), &status));
  base::StringPairs pairs;
  base::SplitStringIntoKeyValuePairs(status, ':', '\n', &pairs);
  for (const auto& pair : pairs) {
    const auto& key = pair.first;
    if (key == "FDSize") {
      const auto value_str =
          base::TrimWhitespaceASCII(pair.second, base::TRIM_ALL);
      int value;
      CHECK(base::StringToInt(value_str, &value));
      return value;
    }
  }
  NOTREACHED();
  return 0;
}

class TestWrapper : public DBusWrapperStub {
 public:
  TestWrapper() = default;
  TestWrapper(const TestWrapper&) = delete;
  TestWrapper& operator=(const TestWrapper&) = delete;

  ~TestWrapper() override = default;

  // Runs |loop_| until battery status is sent through D-Bus.
  bool RunUntilSignalSent(const base::TimeDelta& timeout) {
    return loop_runner_.StartLoop(timeout);
  }

  void EmitBareSignal(const std::string& signal_name) override {
    DBusWrapperStub::EmitBareSignal(signal_name);
    loop_runner_.StopLoop();
  }

  void EmitSignalWithProtocolBuffer(
      const std::string& signal_name,
      const google::protobuf::MessageLite& protobuf) override {
    DBusWrapperStub::EmitSignalWithProtocolBuffer(signal_name, protobuf);
    loop_runner_.StopLoop();
  }

 private:
  TestMainLoopRunner loop_runner_;
};

}  // namespace

class PeripheralBatteryWatcherTest : public TestEnvironment {
 public:
  PeripheralBatteryWatcherTest() = default;
  PeripheralBatteryWatcherTest(const PeripheralBatteryWatcherTest&) = delete;
  PeripheralBatteryWatcherTest& operator=(const PeripheralBatteryWatcherTest&) =
      delete;

  ~PeripheralBatteryWatcherTest() override = default;

  void SetUp() override {
    auto bluez_battery_provider = std::make_unique<MockBluezBatteryProvider>();
    bluez_battery_provider_ = bluez_battery_provider.get();
    battery_.SetBluezBatteryProviderForTest(std::move(bluez_battery_provider));

    CHECK(temp_dir_.CreateUniqueTempDir());

    // Create a fake peripheral directory.
    base::FilePath device_dir =
        temp_dir_.GetPath().Append(kPeripheralBatterySysname);
    CHECK(base::CreateDirectory(device_dir));
    scope_file_ = device_dir.Append(PeripheralBatteryWatcher::kScopeFile);
    WriteFile(scope_file_, PeripheralBatteryWatcher::kScopeValueDevice);
    status_file_ = device_dir.Append(PeripheralBatteryWatcher::kStatusFile);
    model_name_file_ =
        device_dir.Append(PeripheralBatteryWatcher::kModelNameFile);
    WriteFile(model_name_file_, kDeviceModelName);
    peripheral_capacity_file_ =
        device_dir.Append(PeripheralBatteryWatcher::kCapacityFile);
    peripheral_sn_file_ =
        device_dir.Append(PeripheralBatteryWatcher::kSerialNumberFile);

    // Create a fake Bluetooth directory (distinguished by the name)
    device_dir = temp_dir_.GetPath().Append(kBluetoothBatterySysname);
    CHECK(base::CreateDirectory(device_dir));
    WriteFile(device_dir.Append(PeripheralBatteryWatcher::kScopeFile),
              PeripheralBatteryWatcher::kScopeValueDevice);
    WriteFile(device_dir.Append(PeripheralBatteryWatcher::kModelNameFile),
              kDeviceModelName);
    bluetooth_capacity_file_ =
        device_dir.Append(PeripheralBatteryWatcher::kCapacityFile);

    // Create a fake wacom directory.
    device_dir = temp_dir_.GetPath().Append(kWacomBatterySysname);
    CHECK(base::CreateDirectory(device_dir.Append("powers")));
    WriteFile(device_dir.Append(PeripheralBatteryWatcher::kScopeFile),
              PeripheralBatteryWatcher::kScopeValueDevice);
    WriteFile(device_dir.Append(PeripheralBatteryWatcher::kModelNameFile),
              kDeviceModelName);
    wacom_capacity_file_ =
        device_dir.Append(PeripheralBatteryWatcher::kCapacityFile);

    // Create a fake non-peripheral directory (there is no "scope" file.)
    device_dir = temp_dir_.GetPath().Append(kNonPeripheralBatterySysname);
    CHECK(base::CreateDirectory(device_dir));
    WriteFile(device_dir.Append(PeripheralBatteryWatcher::kModelNameFile),
              kDeviceModelName);
    non_peripheral_capacity_file_ =
        device_dir.Append(PeripheralBatteryWatcher::kCapacityFile);

    battery_.set_battery_path_for_testing(temp_dir_.GetPath());
  }

  void TearDown() override {
    // Make sure async file readers are cleaned up.
    task_env()->RunUntilIdle();
  }

 protected:
  void WriteFile(const base::FilePath& path, const string& str) {
    ASSERT_EQ(str.size(), base::WriteFile(path, str.data(), str.size()));
  }

  // TODO(b/215381232): Temporarily support both 'PCHG' name and 'peripheral'
  // name till upstream kernel driver is merged.
  void SetupPeripheralChargerDirectory(bool use_pchg = false) {
    // Create a fake peripheral-charger directory (it is named peripheral.)
    base::FilePath device_dir = temp_dir_.GetPath().Append(
        use_pchg ? kPeripheralChargerBatteryPCHGSysname
                 : kPeripheralChargerBatterySysname);
    CHECK(base::CreateDirectory(device_dir));
    scope_file_ = device_dir.Append(PeripheralBatteryWatcher::kScopeFile);
    WriteFile(scope_file_, PeripheralBatteryWatcher::kScopeValueDevice);

    peripheral_charger_capacity_file_ =
        device_dir.Append(PeripheralBatteryWatcher::kCapacityFile);
    peripheral_charger_status_file_ =
        device_dir.Append(PeripheralBatteryWatcher::kStatusFile);
    peripheral_charger_health_file_ =
        device_dir.Append(PeripheralBatteryWatcher::kHealthFile);
  }

  // Temporary directory mimicking a /sys directory containing a set of sensor
  // devices.
  base::ScopedTempDir temp_dir_;

  base::FilePath scope_file_;
  base::FilePath status_file_;
  base::FilePath peripheral_capacity_file_;
  base::FilePath peripheral_sn_file_;
  base::FilePath model_name_file_;
  base::FilePath non_peripheral_capacity_file_;
  base::FilePath bluetooth_capacity_file_;
  base::FilePath wacom_capacity_file_;
  base::FilePath peripheral_charger_capacity_file_;
  base::FilePath peripheral_charger_status_file_;
  base::FilePath peripheral_charger_health_file_;

  TestWrapper test_wrapper_;

  UdevStub udev_;

  PeripheralBatteryWatcher battery_;
  MockBluezBatteryProvider* bluez_battery_provider_;

  TestMainLoopRunner loop_runner_;
};

TEST_F(PeripheralBatteryWatcherTest, Basic) {
  std::string level = base::NumberToString(80);
  WriteFile(peripheral_capacity_file_, level);
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));

  EXPECT_EQ(1, test_wrapper_.num_sent_signals());
  PeripheralBatteryStatus proto;
  EXPECT_TRUE(test_wrapper_.GetSentSignal(0, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(80, proto.level());
  EXPECT_EQ(kDeviceModelName, proto.name());
  EXPECT_TRUE(proto.has_charge_status());
  EXPECT_EQ(PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_UNKNOWN,
            proto.charge_status());
  EXPECT_TRUE(proto.has_active_update());
  EXPECT_FALSE(proto.active_update());
}

TEST_F(PeripheralBatteryWatcherTest, Bluetooth) {
  std::string level = base::NumberToString(80);
  WriteFile(bluetooth_capacity_file_, level);

  // Bluetooth battery update should not sent any signal, but update to BlueZ.
  EXPECT_CALL(*bluez_battery_provider_,
              UpdateDeviceBattery("11:22:33:aa:bb:cc", 80));
  ON_CALL(*bluez_battery_provider_,
          UpdateDeviceBattery("11:22:33:aa:bb:cc", 80))
      .WillByDefault([this](const std::string& address, int level) {
        this->loop_runner_.StopLoop();
      });
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(loop_runner_.StartLoop(kUpdateTimeout));
  EXPECT_EQ(0, test_wrapper_.num_sent_signals());
}

TEST_F(PeripheralBatteryWatcherTest, Wacom) {
  // Wacom not detected as a Bluetooth device, treat it as a generic peripheral.
  std::string level = base::NumberToString(80);
  WriteFile(wacom_capacity_file_, level);
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));

  EXPECT_EQ(1, test_wrapper_.num_sent_signals());
  PeripheralBatteryStatus proto;
  EXPECT_TRUE(test_wrapper_.GetSentSignal(0, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
}

TEST_F(PeripheralBatteryWatcherTest, WacomWithBluetooth) {
  // Wacom detected as a Bluetooth device (having HID_UNIQ= in powers/uevent).
  base::FilePath device_dir = temp_dir_.GetPath().Append(kWacomBatterySysname);
  WriteFile(device_dir.Append(PeripheralBatteryWatcher::kPowersUeventFile),
            kWacomUevent);
  std::string level = base::NumberToString(70);
  WriteFile(wacom_capacity_file_, level);

  // Bluetooth battery update should not sent any signal, but update to BlueZ.
  EXPECT_CALL(*bluez_battery_provider_,
              UpdateDeviceBattery("aa:aa:aa:aa:aa:aa", 70));
  ON_CALL(*bluez_battery_provider_,
          UpdateDeviceBattery("aa:aa:aa:aa:aa:aa", 70))
      .WillByDefault([this](const std::string& address, int level) {
        this->loop_runner_.StopLoop();
      });
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(loop_runner_.StartLoop(kUpdateTimeout));
  EXPECT_EQ(0, test_wrapper_.num_sent_signals());
}

TEST_F(PeripheralBatteryWatcherTest, NoLevelReading) {
  battery_.Init(&test_wrapper_, &udev_);
  // Without writing battery level to the peripheral_capacity_file_, the loop
  // will timeout.
  EXPECT_FALSE(test_wrapper_.RunUntilSignalSent(kShortUpdateTimeout));
}

TEST_F(PeripheralBatteryWatcherTest, SkipUnknownStatus) {
  // Batteries with unknown statuses should be skipped: http://b/64397082
  WriteFile(peripheral_capacity_file_, base::NumberToString(0));
  WriteFile(status_file_, PeripheralBatteryWatcher::kStatusValueUnknown);
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_FALSE(test_wrapper_.RunUntilSignalSent(kShortUpdateTimeout));
}

TEST_F(PeripheralBatteryWatcherTest, AllowOtherStatus) {
  // Batteries with other statuses should be reported.
  WriteFile(peripheral_capacity_file_, base::NumberToString(20));
  WriteFile(status_file_, PeripheralBatteryWatcher::kStatusValueDischarging);
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));

  EXPECT_EQ(1, test_wrapper_.num_sent_signals());
  PeripheralBatteryStatus proto;
  EXPECT_TRUE(test_wrapper_.GetSentSignal(0, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(20, proto.level());
  EXPECT_TRUE(proto.has_charge_status());
  EXPECT_EQ(PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_DISCHARGING,
            proto.charge_status());
}

TEST_F(PeripheralBatteryWatcherTest, UdevEvents) {
  // Initial reading of battery statuses.
  WriteFile(peripheral_capacity_file_, base::NumberToString(80));
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));

  EXPECT_EQ(1, test_wrapper_.num_sent_signals());
  PeripheralBatteryStatus proto;
  EXPECT_TRUE(test_wrapper_.GetSentSignal(0, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(80, proto.level());
  EXPECT_EQ(kDeviceModelName, proto.name());
  EXPECT_TRUE(proto.has_active_update());
  EXPECT_FALSE(proto.active_update());

  // An udev ADD event appear for a peripheral device.
  WriteFile(peripheral_capacity_file_, base::NumberToString(70));
  udev_.NotifySubsystemObservers({{PeripheralBatteryWatcher::kUdevSubsystem, "",
                                   kPeripheralBatterySysname, ""},
                                  UdevEvent::Action::ADD});
  // Check that powerd reads the battery information and sends an update signal.
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));
  ASSERT_EQ(2, test_wrapper_.num_sent_signals());
  EXPECT_TRUE(test_wrapper_.GetSentSignal(1, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(70, proto.level());
  EXPECT_EQ(kDeviceModelName, proto.name());
  EXPECT_TRUE(proto.has_active_update());
  EXPECT_TRUE(proto.active_update());

  // An udev CHANGE event appear for a peripheral device.
  WriteFile(peripheral_capacity_file_, base::NumberToString(60));
  udev_.NotifySubsystemObservers({{PeripheralBatteryWatcher::kUdevSubsystem, "",
                                   kPeripheralBatterySysname, ""},
                                  UdevEvent::Action::CHANGE});
  // Check that powerd reads the battery information and sends an update signal.
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));
  ASSERT_EQ(3, test_wrapper_.num_sent_signals());
  EXPECT_TRUE(test_wrapper_.GetSentSignal(2, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(60, proto.level());
  EXPECT_EQ(kDeviceModelName, proto.name());
  EXPECT_TRUE(proto.has_active_update());
  EXPECT_TRUE(proto.active_update());

  // An udev REMOVE event appear for a peripheral device.
  WriteFile(peripheral_capacity_file_, base::NumberToString(60));
  udev_.NotifySubsystemObservers({{PeripheralBatteryWatcher::kUdevSubsystem, "",
                                   kPeripheralBatterySysname, ""},
                                  UdevEvent::Action::REMOVE});
  // A REMOVE event should not trigger battery update signal.
  EXPECT_FALSE(test_wrapper_.RunUntilSignalSent(kShortUpdateTimeout));
}

TEST_F(PeripheralBatteryWatcherTest, NonPeripheralUdevEvents) {
  // Initial reading of battery statuses.
  WriteFile(peripheral_capacity_file_, base::NumberToString(80));
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));

  EXPECT_EQ(1, test_wrapper_.num_sent_signals());
  PeripheralBatteryStatus proto;
  EXPECT_TRUE(test_wrapper_.GetSentSignal(0, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(80, proto.level());
  EXPECT_EQ(kDeviceModelName, proto.name());

  // An udev event appear for a non-peripheral device. Check that it is ignored.
  WriteFile(non_peripheral_capacity_file_, base::NumberToString(50));
  udev_.NotifySubsystemObservers({{PeripheralBatteryWatcher::kUdevSubsystem, "",
                                   kNonPeripheralBatterySysname, ""},
                                  UdevEvent::Action::CHANGE});
  EXPECT_FALSE(test_wrapper_.RunUntilSignalSent(kShortUpdateTimeout));
}

TEST_F(PeripheralBatteryWatcherTest, RefreshAllBatteries) {
  std::string level = base::NumberToString(80);
  WriteFile(peripheral_capacity_file_, level);
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));

  EXPECT_EQ(1, test_wrapper_.num_sent_signals());
  PeripheralBatteryStatus proto;
  EXPECT_TRUE(test_wrapper_.GetSentSignal(0, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(80, proto.level());
  EXPECT_EQ(kDeviceModelName, proto.name());
  EXPECT_TRUE(proto.has_charge_status());
  EXPECT_EQ(PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_UNKNOWN,
            proto.charge_status());
  EXPECT_TRUE(proto.has_active_update());
  EXPECT_FALSE(proto.active_update());

  // RefreshAllPeripheralBattery is called.
  dbus::MethodCall method_call(kPowerManagerInterface,
                               kRefreshAllPeripheralBatteryMethod);
  std::unique_ptr<dbus::Response> response =
      test_wrapper_.CallExportedMethodSync(&method_call);
  ASSERT_TRUE(response);
  ASSERT_EQ(dbus::Message::MESSAGE_METHOD_RETURN, response->GetMessageType());

  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));

  EXPECT_EQ(2, test_wrapper_.num_sent_signals());
  EXPECT_TRUE(test_wrapper_.GetSentSignal(1, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));

  EXPECT_EQ(80, proto.level());
  EXPECT_EQ(kDeviceModelName, proto.name());
  EXPECT_TRUE(proto.has_charge_status());
  EXPECT_EQ(PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_UNKNOWN,
            proto.charge_status());
  EXPECT_TRUE(proto.has_active_update());
  EXPECT_FALSE(proto.active_update());
}

TEST_F(PeripheralBatteryWatcherTest, Charger) {
  SetupPeripheralChargerDirectory();
  // Chargers should be reported.
  WriteFile(peripheral_charger_capacity_file_, base::NumberToString(60));
  WriteFile(peripheral_charger_status_file_,
            PeripheralBatteryWatcher::kStatusValueCharging);
  WriteFile(peripheral_charger_health_file_,
            PeripheralBatteryWatcher::kHealthValueGood);
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));

  EXPECT_EQ(1, test_wrapper_.num_sent_signals());
  PeripheralBatteryStatus proto;
  EXPECT_TRUE(test_wrapper_.GetSentSignal(0, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(60, proto.level());
  EXPECT_EQ(PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_CHARGING,
            proto.charge_status());
}

TEST_F(PeripheralBatteryWatcherTest, ChargerFull) {
  SetupPeripheralChargerDirectory();
  // Chargers should be reported.
  WriteFile(peripheral_charger_capacity_file_, base::NumberToString(100));
  WriteFile(peripheral_charger_status_file_,
            PeripheralBatteryWatcher::kStatusValueFull);
  WriteFile(peripheral_charger_health_file_,
            PeripheralBatteryWatcher::kHealthValueGood);
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));

  EXPECT_EQ(1, test_wrapper_.num_sent_signals());
  PeripheralBatteryStatus proto;
  EXPECT_TRUE(test_wrapper_.GetSentSignal(0, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(100, proto.level());
  EXPECT_TRUE(proto.has_charge_status());
  EXPECT_EQ(PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_FULL,
            proto.charge_status());
}

TEST_F(PeripheralBatteryWatcherTest, ChargerDetached) {
  SetupPeripheralChargerDirectory();
  // Chargers should be reported.
  WriteFile(peripheral_charger_capacity_file_, base::NumberToString(0));
  WriteFile(peripheral_charger_status_file_,
            PeripheralBatteryWatcher::kStatusValueUnknown);
  // Leave health missing
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));

  EXPECT_EQ(1, test_wrapper_.num_sent_signals());
  PeripheralBatteryStatus proto;
  EXPECT_TRUE(test_wrapper_.GetSentSignal(0, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(0, proto.level());
  EXPECT_TRUE(proto.has_charge_status());
  EXPECT_EQ(PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_UNKNOWN,
            proto.charge_status());
}

TEST_F(PeripheralBatteryWatcherTest, ChargerError) {
  SetupPeripheralChargerDirectory();
  // Chargers health error should be reported.
  WriteFile(peripheral_charger_capacity_file_, base::NumberToString(50));
  WriteFile(peripheral_charger_status_file_,
            PeripheralBatteryWatcher::kStatusValueCharging);
  WriteFile(peripheral_charger_health_file_, "Hot");
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));

  EXPECT_EQ(1, test_wrapper_.num_sent_signals());
  PeripheralBatteryStatus proto;
  EXPECT_TRUE(test_wrapper_.GetSentSignal(0, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(50, proto.level());
  EXPECT_TRUE(proto.has_charge_status());
  EXPECT_EQ(PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_ERROR,
            proto.charge_status());
}

// TODO(b/215381232): Temporarily support both 'PCHG' name and 'peripheral' name
// till upstream kernel driver is merged. Remove test case when upstream kernel
// driver is merged.
TEST_F(PeripheralBatteryWatcherTest, Charger_PCHG) {
  SetupPeripheralChargerDirectory(/*use_pchg=*/true);

  // Chargers should be reported.
  WriteFile(peripheral_charger_capacity_file_, base::NumberToString(60));
  WriteFile(peripheral_charger_status_file_,
            PeripheralBatteryWatcher::kStatusValueCharging);
  WriteFile(peripheral_charger_health_file_,
            PeripheralBatteryWatcher::kHealthValueGood);
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));

  EXPECT_EQ(1, test_wrapper_.num_sent_signals());
  PeripheralBatteryStatus proto;
  EXPECT_TRUE(test_wrapper_.GetSentSignal(0, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(60, proto.level());
  EXPECT_EQ(PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_CHARGING,
            proto.charge_status());
}

// TODO(b/215381232): Temporarily support both 'PCHG' name and 'peripheral' name
// till upstream kernel driver is merged.Remove test case when upstream kernel
// driver is merged.
TEST_F(PeripheralBatteryWatcherTest, ChargerFull_PCHG) {
  SetupPeripheralChargerDirectory(/*use_pchg=*/true);

  // Chargers should be reported.
  WriteFile(peripheral_charger_capacity_file_, base::NumberToString(100));
  WriteFile(peripheral_charger_status_file_,
            PeripheralBatteryWatcher::kStatusValueFull);
  WriteFile(peripheral_charger_health_file_,
            PeripheralBatteryWatcher::kHealthValueGood);
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));

  EXPECT_EQ(1, test_wrapper_.num_sent_signals());
  PeripheralBatteryStatus proto;
  EXPECT_TRUE(test_wrapper_.GetSentSignal(0, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(100, proto.level());
  EXPECT_TRUE(proto.has_charge_status());
  EXPECT_EQ(PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_FULL,
            proto.charge_status());
}

TEST_F(PeripheralBatteryWatcherTest, UdevEventsWithoutSerial) {
  // TODO(kenalba): trim this down
  // Initial reading of battery statuses.
  WriteFile(peripheral_capacity_file_, base::NumberToString(80));
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));

  EXPECT_EQ(1, test_wrapper_.num_sent_signals());
  PeripheralBatteryStatus proto;
  EXPECT_TRUE(test_wrapper_.GetSentSignal(0, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(80, proto.level());
  EXPECT_EQ(kDeviceModelName, proto.name());
  EXPECT_TRUE(proto.has_active_update());
  EXPECT_FALSE(proto.active_update());
  EXPECT_FALSE(proto.has_serial_number());

  // An udev ADD event appear for a peripheral device.
  WriteFile(peripheral_capacity_file_, base::NumberToString(70));
  udev_.NotifySubsystemObservers({{PeripheralBatteryWatcher::kUdevSubsystem, "",
                                   kPeripheralBatterySysname, ""},
                                  UdevEvent::Action::ADD});
  // Check that powerd reads the battery information and sends an update signal.
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));
  ASSERT_EQ(2, test_wrapper_.num_sent_signals());
  EXPECT_TRUE(test_wrapper_.GetSentSignal(1, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(70, proto.level());
  EXPECT_EQ(kDeviceModelName, proto.name());
  EXPECT_TRUE(proto.has_active_update());
  EXPECT_TRUE(proto.active_update());
  EXPECT_FALSE(proto.has_serial_number());

  // An udev CHANGE event appear for a peripheral device.
  WriteFile(peripheral_capacity_file_, base::NumberToString(60));
  udev_.NotifySubsystemObservers({{PeripheralBatteryWatcher::kUdevSubsystem, "",
                                   kPeripheralBatterySysname, ""},
                                  UdevEvent::Action::CHANGE});
  // Check that powerd reads the battery information and sends an update signal.
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));
  ASSERT_EQ(3, test_wrapper_.num_sent_signals());
  EXPECT_TRUE(test_wrapper_.GetSentSignal(2, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(60, proto.level());
  EXPECT_EQ(kDeviceModelName, proto.name());
  EXPECT_TRUE(proto.has_active_update());
  EXPECT_TRUE(proto.active_update());
  EXPECT_FALSE(proto.has_serial_number());
  // An udev REMOVE event appear for a peripheral device.
  WriteFile(peripheral_capacity_file_, base::NumberToString(60));
  udev_.NotifySubsystemObservers({{PeripheralBatteryWatcher::kUdevSubsystem, "",
                                   kPeripheralBatterySysname, ""},
                                  UdevEvent::Action::REMOVE});
  // A REMOVE event should not trigger battery update signal.
  EXPECT_FALSE(test_wrapper_.RunUntilSignalSent(kShortUpdateTimeout));
}

TEST_F(PeripheralBatteryWatcherTest, UdevEventsWithSerial) {
  // TODO(kenalba): trim this down
  // Initial reading of battery statuses.
  WriteFile(peripheral_capacity_file_, base::NumberToString(80));
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));

  EXPECT_EQ(1, test_wrapper_.num_sent_signals());
  PeripheralBatteryStatus proto;
  EXPECT_TRUE(test_wrapper_.GetSentSignal(0, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(80, proto.level());
  EXPECT_EQ(kDeviceModelName, proto.name());
  EXPECT_TRUE(proto.has_active_update());
  EXPECT_FALSE(proto.active_update());
  EXPECT_FALSE(proto.has_serial_number());

  // An udev ADD event appear for a peripheral device.
  WriteFile(peripheral_capacity_file_, base::NumberToString(70));
  WriteFile(peripheral_sn_file_, kPeripheralBatterySerialNumber1);
  udev_.NotifySubsystemObservers({{PeripheralBatteryWatcher::kUdevSubsystem, "",
                                   kPeripheralBatterySysname, ""},
                                  UdevEvent::Action::ADD});
  // Check that powerd reads the battery information and sends an update signal.
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));
  ASSERT_EQ(2, test_wrapper_.num_sent_signals());
  EXPECT_TRUE(test_wrapper_.GetSentSignal(1, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(70, proto.level());
  EXPECT_EQ(kDeviceModelName, proto.name());
  EXPECT_TRUE(proto.has_active_update());
  EXPECT_TRUE(proto.active_update());
  EXPECT_TRUE(proto.has_active_update());
  EXPECT_TRUE(proto.has_serial_number());
  EXPECT_EQ(kPeripheralBatterySerialNumber1, proto.serial_number());

  // An udev CHANGE event appear for a peripheral device.
  WriteFile(peripheral_capacity_file_, base::NumberToString(60));
  WriteFile(peripheral_sn_file_, kPeripheralBatterySerialNumber2);
  udev_.NotifySubsystemObservers({{PeripheralBatteryWatcher::kUdevSubsystem, "",
                                   kPeripheralBatterySysname, ""},
                                  UdevEvent::Action::CHANGE});
  // Check that powerd reads the battery information and sends an update signal.
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));
  ASSERT_EQ(3, test_wrapper_.num_sent_signals());
  EXPECT_TRUE(test_wrapper_.GetSentSignal(2, kPeripheralBatteryStatusSignal,
                                          &proto, nullptr));
  EXPECT_EQ(60, proto.level());
  EXPECT_EQ(kDeviceModelName, proto.name());
  EXPECT_TRUE(proto.has_active_update());
  EXPECT_TRUE(proto.active_update());
  EXPECT_TRUE(proto.has_serial_number());
  EXPECT_EQ(kPeripheralBatterySerialNumber2, proto.serial_number());

  // An udev REMOVE event appear for a peripheral device.
  WriteFile(peripheral_capacity_file_, base::NumberToString(60));
  udev_.NotifySubsystemObservers({{PeripheralBatteryWatcher::kUdevSubsystem, "",
                                   kPeripheralBatterySysname, ""},
                                  UdevEvent::Action::REMOVE});
  // A REMOVE event should not trigger battery update signal.
  EXPECT_FALSE(test_wrapper_.RunUntilSignalSent(kShortUpdateTimeout));
}

TEST_F(PeripheralBatteryWatcherTest, SpammyUdevEvents) {
  // This is a regression test to make sure we don't keep opening new file
  // descriptors in response to the same udev device being reconnected many
  // times.
  WriteFile(peripheral_capacity_file_, base::NumberToString(50));
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));

  const size_t kDevicesToAdd = 128;
  int fd_count = GetNumberOfOpenFiles();
  rlimit rlim_orig;
  getrlimit(RLIMIT_NOFILE, &rlim_orig);

  // Temporarily drop the open file count limit.
  rlimit rlim = rlim_orig;
  rlim.rlim_cur = fd_count + kDevicesToAdd / 2;
  setrlimit(RLIMIT_NOFILE, &rlim);

  for (size_t i = 0; i < kDevicesToAdd; i++) {
    udev_.NotifySubsystemObservers({{PeripheralBatteryWatcher::kUdevSubsystem,
                                     "", kPeripheralBatterySysname, ""},
                                    UdevEvent::Action::ADD});
  }

  // Make sure we didn't leak file descriptors and can still open a file.
  WriteFile(peripheral_capacity_file_, base::NumberToString(40));

  // Restore the original file count limit.
  setrlimit(RLIMIT_NOFILE, &rlim_orig);
}

TEST_F(PeripheralBatteryWatcherTest, ReadLatencyMetrics) {
  StrictMock<MetricsLibraryMock> metrics_lib;
  MetricsSender metrics_sender{metrics_lib};

  EXPECT_CALL(metrics_lib, SendToUMA("Power.PeripheralReadLatencyMs", Gt(0),
                                     metrics::kPeripheralReadLatencyMsMin,
                                     metrics::kPeripheralReadLatencyMsMax,
                                     metrics::kDefaultBuckets))
      .Times(1)
      .WillOnce(Return(true))
      .RetiresOnSaturation();

  WriteFile(peripheral_capacity_file_, base::NumberToString(50));
  battery_.Init(&test_wrapper_, &udev_);
  ASSERT_TRUE(test_wrapper_.RunUntilSignalSent(kUpdateTimeout));
}

}  // namespace power_manager::system
