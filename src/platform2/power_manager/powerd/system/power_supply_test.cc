// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/power_supply.h"

#include <algorithm>
#include <cmath>
#include <iterator>
#include <map>
#include <memory>
#include <string>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>
#include <libec/display_soc_command.h>
#include <libec/mock_ec_command_factory.h>

#include "power_manager/common/battery_percentage_converter.h"
#include "power_manager/common/fake_prefs.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/common/test_main_loop_runner.h"
#include "power_manager/powerd/system/dbus_wrapper_stub.h"
#include "power_manager/powerd/system/udev_stub.h"
#include "power_manager/powerd/testing/test_environment.h"
#include "power_manager/proto_bindings/power_supply_properties.pb.h"

using ::testing::_;
using ::testing::Return;

namespace power_manager::system {

namespace {

using Role = PowerStatus::Port::Role;

const char* const kMainsType = PowerSupply::kMainsType;
const char* const kBatteryType = PowerSupply::kBatteryType;
const char* const kUsbType = PowerSupply::kUsbType;
const char* const kUsbPdType = PowerSupply::kUsbPdType;
const char* const kUsbPdDrpType = PowerSupply::kUsbPdDrpType;
const char* const kUnknownType = PowerSupply::kUnknownType;

const char* const kCharging = PowerSupply::kBatteryStatusCharging;
const char* const kDischarging = PowerSupply::kBatteryStatusDischarging;
const char* const kNotCharging = PowerSupply::kBatteryStatusNotCharging;

// Default values reported by sysfs.
constexpr double kDefaultCurrent = 1.0;
constexpr double kDefaultCharge = 1.0;
constexpr double kDefaultChargeFull = 1.0;
constexpr double kDefaultChargeFullDesign = 1.0;
constexpr double kDefaultSecondCurrent = 0.5;
constexpr double kDefaultSecondCharge = 2.0;
constexpr double kDefaultSecondChargeFull = 3.0;
constexpr double kDefaultSecondChargeFullDesign = 4.0;
constexpr double kVoltage = 2.5;
constexpr double kVoltageMinDesign = 2.0;
constexpr int64_t kCycleCount = 10000;
constexpr char kSerialNumber[] = "1000";
// Default value for kPowerSupplyFullFactorPref.
constexpr double kFullFactor = 0.98;

// Values reported by udev
const char* const kUdevSubsystemAC = "AC";
const char* const kUdevSubsystemBAT0 = "BAT0";
const char* const kUdevSubsystemBAT1 = "BAT1";
const char* const kUdevSubsystemUSBPD0 = "CROS_USBPD_CHARGER0";

// Starting value used by |power_supply_| as "now".
const base::TimeTicks kStartTime = base::TimeTicks() + base::Microseconds(1000);

// Invalid values for usb_type.
const char* kInvalidUsbTypeValues[] = {
    "Unknown SDP DCP CDP C PD PD_DRP BrickID",
    "Unknown SDP DCP CDP C PD [] BrickID",
    "Unknown SDP DCP CDP C PD ]PD_DRP[ BrickID",
    "[",
    "]",
    "[]"};

class TestObserver : public PowerSupplyObserver {
 public:
  explicit TestObserver(PowerSupply* power_supply)
      : power_supply_(power_supply) {
    power_supply_->AddObserver(this);
  }
  TestObserver(const TestObserver&) = delete;
  TestObserver& operator=(const TestObserver&) = delete;

  ~TestObserver() override { power_supply_->RemoveObserver(this); }

  int num_updates() const { return num_updates_; }
  void reset_num_updates() { num_updates_ = 0; }

  // Runs the event loop until OnPowerStatusUpdate() is invoked or a timeout is
  // hit. Returns true if the method was invoked and false if it wasn't.
  bool WaitForNotification() { return runner_.StartLoop(base::Seconds(10)); }

  // PowerSupplyObserver overrides:
  void OnPowerStatusUpdate() override {
    num_updates_++;
    if (runner_.LoopIsRunning())
      runner_.StopLoop();
  }

 private:
  PowerSupply* power_supply_ = nullptr;  // Not owned.

  // Number of times that OnPowerStatusUpdate() has been called.
  int num_updates_ = 0;

  TestMainLoopRunner runner_;
};

class MockDisplayStateOfChargeCommand : public ec::DisplayStateOfChargeCommand {
 public:
  MOCK_METHOD(bool, Run, (int fd));
};

}  // namespace

class PowerSupplyTest : public TestEnvironment {
 public:
  PowerSupplyTest() = default;

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    ASSERT_TRUE(temp_dir_.IsValid());

    // Create the CrOS EC file.
    cros_ec_path_ = temp_dir_.GetPath().Append("cros_ec");
    EXPECT_EQ(0, base::WriteFile(cros_ec_path_, "", 0));

    // Leave support for fetching the Display state of charge from the EC off by
    // default.
    ON_CALL(ec_command_factory_, DisplayStateOfChargeCommand)
        .WillByDefault([]() {
          auto cmd = std::make_unique<MockDisplayStateOfChargeCommand>();
          EXPECT_CALL(*cmd, Run(_)).WillOnce(Return(false));
          return cmd;
        });

    prefs_.SetInt64(kLowBatteryShutdownTimePref, 180);
    prefs_.SetDouble(kPowerSupplyFullFactorPref, kFullFactor);
    prefs_.SetInt64(kMaxCurrentSamplesPref, 5);
    prefs_.SetInt64(kMaxChargeSamplesPref, 5);

    power_supply_ = std::make_unique<PowerSupply>();
    test_api_ = std::make_unique<PowerSupply::TestApi>(power_supply_.get());
    test_api_->SetCurrentTime(kStartTime);

    ac_dir_ = temp_dir_.GetPath().Append("AC");
    usbpd_dir_ = temp_dir_.GetPath().Append("CROS_USBPD_CHARGER0");
    battery_dir_ = temp_dir_.GetPath().Append("battery");
    second_battery_dir_ = temp_dir_.GetPath().Append("battery_2");
  }

 protected:
  void Init() {
    battery_percentage_converter_ =
        BatteryPercentageConverter::CreateFromPrefs(&prefs_);

    power_supply_->Init(temp_dir_.GetPath(), cros_ec_path_,
                        &ec_command_factory_, &prefs_, &udev_, &dbus_wrapper_,
                        battery_percentage_converter_.get());
  }

  // Sets the time so that |power_supply_| will believe that the current
  // has stabilized.
  void SetStabilizedTime() {
    const base::TimeTicks now = test_api_->GetCurrentTime();
    if (power_supply_->battery_stabilized_timestamp() > now)
      test_api_->SetCurrentTime(power_supply_->battery_stabilized_timestamp());
  }

  // Writes |value| to |filename| within |dir_|.
  void WriteValue(const base::FilePath& dir,
                  const std::string& filename,
                  const std::string& value) {
    CHECK(base::WriteFile(dir.Append(filename), value.c_str(), value.length()));
  }

  // Converts |value| to the format used by sysfs and passes it to WriteValue().
  void WriteDoubleValue(const base::FilePath& dir,
                        const std::string& filename,
                        double value) {
    // sysfs stores doubles by multiplying them by 1000000.
    const int int_value = round(value * 1000000);
    WriteValue(dir, filename, base::NumberToString(int_value));
  }

  // Writes reasonable default values to |temp_dir_|.
  // The battery's max charge is initialized to 1.0 to make things simple.
  void WriteDefaultValues(PowerSource source) {
    ASSERT_TRUE(base::CreateDirectory(ac_dir_));
    ASSERT_TRUE(base::CreateDirectory(battery_dir_));

    UpdatePowerSourceAndBatteryStatus(
        source, kMainsType,
        source == PowerSource::AC ? kCharging : kDischarging);
    WriteValue(battery_dir_, "type", kBatteryType);
    WriteValue(battery_dir_, "present", "1");

    UpdateChargeAndCurrent(kDefaultCharge, kDefaultCurrent);
    WriteDoubleValue(battery_dir_, "charge_full", kDefaultChargeFull);
    WriteDoubleValue(battery_dir_, "charge_full_design",
                     kDefaultChargeFullDesign);
    WriteDoubleValue(battery_dir_, "voltage_now", kVoltage);
    WriteDoubleValue(battery_dir_, "voltage_min_design", kVoltage);
    WriteValue(battery_dir_, "cycle_count", base::NumberToString(kCycleCount));
    WriteValue(battery_dir_, "serial_number", kSerialNumber);
    prefs_.SetDouble(kUsbMinAcWattsPref, 23.45);
    prefs_.SetBool(kHasBarreljackPref, true);
  }

  // Updates the files describing the power source and battery status.
  void UpdatePowerSourceAndBatteryStatus(PowerSource power_source,
                                         const std::string& ac_type,
                                         const std::string& battery_status) {
    WriteValue(ac_dir_, "online", power_source == PowerSource::AC ? "1" : "0");
    WriteValue(ac_dir_, "type", ac_type);
    WriteValue(battery_dir_, "status", battery_status);
  }

  // Updates the files describing |dir|'s charge and current.
  void UpdateChargeAndCurrentForDir(const base::FilePath& dir,
                                    double charge,
                                    double current) {
    WriteDoubleValue(dir, "charge_now", charge);
    WriteDoubleValue(dir, "current_now", current);
  }

  // Updates the files describing |battery_dir_|'s charge and current.
  void UpdateChargeAndCurrent(double charge, double current) {
    UpdateChargeAndCurrentForDir(battery_dir_, charge, current);
  }

  // Writes base files for a second battery at |second_battery_dir_|.
  void AddSecondBattery(const std::string& status) {
    ASSERT_TRUE(base::CreateDirectory(second_battery_dir_));
    WriteValue(second_battery_dir_, "type", kBatteryType);
    WriteValue(second_battery_dir_, "present", "1");
    WriteValue(second_battery_dir_, "status", status);
    WriteDoubleValue(second_battery_dir_, "current_now", kDefaultSecondCurrent);
    WriteDoubleValue(second_battery_dir_, "charge_now", kDefaultSecondCharge);
    WriteDoubleValue(second_battery_dir_, "charge_full",
                     kDefaultSecondChargeFull);
    WriteDoubleValue(second_battery_dir_, "charge_full_design",
                     kDefaultSecondChargeFullDesign);
    WriteDoubleValue(second_battery_dir_, "voltage_now", kVoltage);
    WriteDoubleValue(second_battery_dir_, "voltage_min_design", kVoltage);
  }

  void AddUSBPDCharger(const bool charging) {
    ASSERT_TRUE(base::CreateDirectory(usbpd_dir_));
    WriteValue(usbpd_dir_, "type", "USB");
    WriteValue(usbpd_dir_, "online", "1");
  }

  // Returns a string describing battery estimates. If |time_to_empty_sec| is
  // nonzero, the appropriate time-to-shutdown estimate will be calculated
  // based on kLowBatteryShutdownTimePref.
  std::string MakeEstimateString(bool calculating,
                                 int time_to_empty_sec,
                                 int time_to_full_sec) {
    int time_to_shutdown_sec = time_to_empty_sec;
    int64_t shutdown_sec = 0;
    if (time_to_empty_sec > 0 &&
        prefs_.GetInt64(kLowBatteryShutdownTimePref, &shutdown_sec)) {
      time_to_shutdown_sec =
          std::max(time_to_empty_sec - static_cast<int>(shutdown_sec), 0);
    }
    return base::StringPrintf("calculating=%d empty=%d shutdown=%d full=%d",
                              calculating, time_to_empty_sec,
                              time_to_shutdown_sec, time_to_full_sec);
  }

  std::string GetEstimateStringFromStatus(const PowerStatus& status) {
    return base::StringPrintf(
        "calculating=%d empty=%d shutdown=%d full=%d",
        status.is_calculating_battery_time,
        static_cast<int>(status.battery_time_to_empty.InSeconds()),
        static_cast<int>(status.battery_time_to_shutdown.InSeconds()),
        static_cast<int>(status.battery_time_to_full.InSeconds()));
  }

  // Call UpdateStatus() and return a string describing the returned battery
  // estimates, suitable for comparison with a string built via
  // MakeEstimateString().
  std::string UpdateAndGetEstimateString() {
    PowerStatus status;
    if (!UpdateStatus(&status))
      return std::string();
    return GetEstimateStringFromStatus(status);
  }

  // Refreshes and updates |status|. Returns false if the refresh failed (but
  // still copies |power_supply_|'s current status to |status|).
  [[nodiscard]] bool UpdateStatus(PowerStatus* status) {
    CHECK(status);
    const bool success = power_supply_->RefreshImmediately();
    *status = power_supply_->GetPowerStatus();
    return success;
  }

  // Sends a udev event to |power_supply_|.
  void SendUdevEvent(const std::string& sysname) {
    udev_.NotifySubsystemObservers(
        {{PowerSupply::kUdevSubsystem, "", sysname, ""},
         UdevEvent::Action::CHANGE});
  }

  // Makes a SetPowerSource D-Bus method call and returns true if the call was
  // successful or false if it failed.
  [[nodiscard]] bool CallSetPowerSource(const std::string& id) {
    dbus::MethodCall method_call(kPowerManagerInterface, kSetPowerSourceMethod);
    dbus::MessageWriter(&method_call).AppendString(id);
    std::unique_ptr<dbus::Response> response =
        dbus_wrapper_.CallExportedMethodSync(&method_call);
    return response &&
           response->GetMessageType() != dbus::Message::MESSAGE_ERROR;
  }

  FakePrefs prefs_;
  ec::MockEcCommandFactory ec_command_factory_;
  base::ScopedTempDir temp_dir_;
  base::FilePath cros_ec_path_;
  base::FilePath ac_dir_;
  base::FilePath usbpd_dir_;
  base::FilePath battery_dir_;
  base::FilePath second_battery_dir_;
  UdevStub udev_;
  DBusWrapperStub dbus_wrapper_;
  std::unique_ptr<BatteryPercentageConverter> battery_percentage_converter_;
  std::unique_ptr<PowerSupply> power_supply_;
  std::unique_ptr<PowerSupply::TestApi> test_api_;
};

TEST(PowerSupplyStaticTest, ConnectedSourcesAreEqual) {
  // Equality should be reported when no ports are found.
  PowerStatus a, b;
  EXPECT_TRUE(PowerSupply::ConnectedSourcesAreEqual(a, b));

  // A disconnected port should be disregarded.
  constexpr char kId1[] = "ID1";
  a.ports.emplace_back();
  a.ports[0].id = kId1;
  EXPECT_TRUE(PowerSupply::ConnectedSourcesAreEqual(a, b));
  EXPECT_TRUE(PowerSupply::ConnectedSourcesAreEqual(b, a));

  // After the port is connected, |a| and |b|'s connected sources no longer
  // match.
  a.ports[0].role = Role::DEDICATED_SOURCE;
  EXPECT_FALSE(PowerSupply::ConnectedSourcesAreEqual(a, b));
  EXPECT_FALSE(PowerSupply::ConnectedSourcesAreEqual(b, a));

  // A disconnected port that's added to |b| should be ignored.
  b.ports.emplace_back();
  b.ports[0].id = kId1;
  EXPECT_FALSE(PowerSupply::ConnectedSourcesAreEqual(a, b));
  EXPECT_FALSE(PowerSupply::ConnectedSourcesAreEqual(b, a));

  // Once |b|'s port is connected, the statuses should match again.
  b.ports[0].role = Role::DEDICATED_SOURCE;
  EXPECT_TRUE(PowerSupply::ConnectedSourcesAreEqual(a, b));
  EXPECT_TRUE(PowerSupply::ConnectedSourcesAreEqual(b, a));

  // Insert a new disconnected port at the beginning of |a|'s list and check
  // that the statuses are still reported as being equal.
  constexpr char kId0[] = "ID0";
  a.ports.insert(a.ports.begin(), PowerStatus::Port());
  a.ports[0].id = kId0;
  EXPECT_TRUE(PowerSupply::ConnectedSourcesAreEqual(a, b));
  EXPECT_TRUE(PowerSupply::ConnectedSourcesAreEqual(b, a));

  // If the new port is connected, the statuses should be unequal again.
  a.ports[0].role = Role::DEDICATED_SOURCE;
  EXPECT_FALSE(PowerSupply::ConnectedSourcesAreEqual(a, b));
  EXPECT_FALSE(PowerSupply::ConnectedSourcesAreEqual(b, a));

  // Give |b| a port with a different ID and check that the statuses are still
  // unequal.
  constexpr char kId0B[] = "ID0B";
  b.ports.insert(b.ports.begin(), PowerStatus::Port());
  b.ports[0].id = kId0B;
  b.ports[0].role = Role::DEDICATED_SOURCE;

  // Now update the ID and check that they're equal again.
  b.ports[0].id = kId0;
  EXPECT_TRUE(PowerSupply::ConnectedSourcesAreEqual(a, b));
  EXPECT_TRUE(PowerSupply::ConnectedSourcesAreEqual(b, a));

  // The ports' role types also need to match.
  a.ports[0].role = Role::DUAL_ROLE;
  EXPECT_FALSE(PowerSupply::ConnectedSourcesAreEqual(a, b));
  EXPECT_FALSE(PowerSupply::ConnectedSourcesAreEqual(b, a));
  b.ports[0].role = Role::DUAL_ROLE;
  EXPECT_TRUE(PowerSupply::ConnectedSourcesAreEqual(a, b));
  EXPECT_TRUE(PowerSupply::ConnectedSourcesAreEqual(b, a));

  // Ditto for |type| values.
  a.ports[0].type = kMainsType;
  EXPECT_FALSE(PowerSupply::ConnectedSourcesAreEqual(a, b));
  EXPECT_FALSE(PowerSupply::ConnectedSourcesAreEqual(b, a));
  b.ports[0].type = kMainsType;
  EXPECT_TRUE(PowerSupply::ConnectedSourcesAreEqual(a, b));
  EXPECT_TRUE(PowerSupply::ConnectedSourcesAreEqual(b, a));
}

// Test system without power supply sysfs (e.g. virtual machine).
TEST_F(PowerSupplyTest, NoPowerSupplySysfs) {
  Init();
  PowerStatus power_status;
  ASSERT_TRUE(UpdateStatus(&power_status));
  // In absence of power supply sysfs, default assumption is line power on, no
  // battery present.
  EXPECT_TRUE(power_status.line_power_on);
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC,
            power_status.external_power);
  EXPECT_FALSE(power_status.battery_is_present);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_NOT_PRESENT,
            power_status.battery_state);
}

// Test line power without battery.
TEST_F(PowerSupplyTest, NoBattery) {
  WriteDefaultValues(PowerSource::AC);
  base::DeletePathRecursively(battery_dir_);
  Init();
  PowerStatus power_status;
  ASSERT_TRUE(UpdateStatus(&power_status));
  EXPECT_TRUE(power_status.line_power_on);
  EXPECT_EQ(kMainsType, power_status.line_power_type);
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC,
            power_status.external_power);
  EXPECT_FALSE(power_status.battery_is_present);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_NOT_PRESENT,
            power_status.battery_state);
  EXPECT_FALSE(power_status.supports_dual_role_devices);
}

// Test battery charging and discharging status.
TEST_F(PowerSupplyTest, ChargingAndDischarging) {
  const double kCharge = 0.5;
  const double kCurrent = 1.0;
  WriteDefaultValues(PowerSource::AC);
  UpdateChargeAndCurrent(kCharge, kCurrent);
  Init();
  PowerStatus power_status;
  ASSERT_TRUE(UpdateStatus(&power_status));
  EXPECT_TRUE(power_status.line_power_on);
  EXPECT_EQ(kMainsType, power_status.line_power_type);
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC,
            power_status.external_power);
  EXPECT_TRUE(power_status.battery_is_present);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_CHARGING,
            power_status.battery_state);
  EXPECT_DOUBLE_EQ(kCharge * kVoltage, power_status.battery_energy);
  EXPECT_DOUBLE_EQ(kCurrent * kVoltage, power_status.battery_energy_rate);
  EXPECT_DOUBLE_EQ(50.0, power_status.battery_percentage);
  EXPECT_FALSE(power_status.supports_dual_role_devices);

  // Switch to battery.
  UpdatePowerSourceAndBatteryStatus(PowerSource::BATTERY, kMainsType,
                                    kDischarging);
  ASSERT_TRUE(UpdateStatus(&power_status));
  EXPECT_FALSE(power_status.line_power_on);
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_DISCONNECTED,
            power_status.external_power);
  EXPECT_TRUE(power_status.battery_is_present);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_DISCHARGING,
            power_status.battery_state);
  EXPECT_DOUBLE_EQ(kCharge * kVoltage, power_status.battery_energy);
  EXPECT_DOUBLE_EQ(kCurrent * kVoltage, power_status.battery_energy_rate);
  EXPECT_DOUBLE_EQ(50.0, power_status.battery_percentage);
  EXPECT_EQ(kCycleCount, power_status.battery_cycle_count);
  EXPECT_EQ(kSerialNumber, power_status.battery_serial_number);
  EXPECT_DOUBLE_EQ(kDefaultChargeFullDesign,
                   power_status.battery_charge_full_design);
  EXPECT_DOUBLE_EQ(kDefaultChargeFull, power_status.battery_charge_full);
  EXPECT_DOUBLE_EQ(kVoltage, power_status.battery_voltage_min_design);
  EXPECT_DOUBLE_EQ(kDefaultChargeFullDesign * kVoltage,
                   power_status.battery_energy_full_design);
  EXPECT_DOUBLE_EQ(kDefaultChargeFull * kVoltage,
                   power_status.battery_energy_full);

  // Test with a negative current.
  UpdateChargeAndCurrent(kCharge, -kCurrent);
  ASSERT_TRUE(UpdateStatus(&power_status));
  EXPECT_EQ(PowerSupplyProperties_BatteryState_DISCHARGING,
            power_status.battery_state);
  EXPECT_DOUBLE_EQ(kCharge * kVoltage, power_status.battery_energy);
  EXPECT_DOUBLE_EQ(kCurrent * kVoltage, power_status.battery_energy_rate);
}

TEST_F(PowerSupplyTest, EnergyFullNominalVoltageNotEqualVoltage) {
  WriteDefaultValues(PowerSource::BATTERY);
  base::DeleteFile(battery_dir_.Append("voltage_min_design"));
  WriteDoubleValue(battery_dir_, "voltage_min_design", kVoltageMinDesign);
  Init();
  PowerStatus power_status;
  ASSERT_TRUE(UpdateStatus(&power_status));
  EXPECT_DOUBLE_EQ(kVoltageMinDesign, power_status.nominal_voltage);
  EXPECT_DOUBLE_EQ(kDefaultChargeFullDesign * kVoltageMinDesign,
                   power_status.battery_energy_full_design);
  EXPECT_DOUBLE_EQ(kDefaultChargeFull * kVoltageMinDesign,
                   power_status.battery_energy_full);
}

// Tests that the line power source doesn't need to be named "Mains".
TEST_F(PowerSupplyTest, NonMainsLinePower) {
  const char kType[] = "ArbitraryName";
  WriteDefaultValues(PowerSource::AC);
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kType, kCharging);
  Init();
  PowerStatus power_status;
  ASSERT_TRUE(UpdateStatus(&power_status));
  EXPECT_TRUE(power_status.line_power_on);
  EXPECT_EQ(kType, power_status.line_power_type);
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC,
            power_status.external_power);
  EXPECT_TRUE(power_status.battery_is_present);
  EXPECT_FALSE(power_status.supports_dual_role_devices);
}

// Test that the supply type is correctly read from usb_type when present.
TEST_F(PowerSupplyTest, LinePowerWithUsbType) {
  WriteDefaultValues(PowerSource::AC);
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kUsbType, kCharging);
  Init();

  // With the type set to USB and no usb_type set, the supply is treated
  // as a low-power USB connection.
  PowerStatus power_status;
  ASSERT_TRUE(UpdateStatus(&power_status));
  EXPECT_EQ(kUsbType, power_status.ports[0].type);
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_USB,
            power_status.external_power);

  // With usb_type set to PD, the supply is treated as AC.
  WriteValue(ac_dir_, "usb_type", "C [PD] PD_PPS");
  ASSERT_TRUE(UpdateStatus(&power_status));
  EXPECT_EQ(kUsbPdType, power_status.ports[0].type);
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC,
            power_status.external_power);

  // Invalid usb_type values should report as low-power USB.
  for (const char* const kType : kInvalidUsbTypeValues) {
    SCOPED_TRACE(kType);
    WriteValue(ac_dir_, "usb_type", kType);
    ASSERT_TRUE(UpdateStatus(&power_status));
    ASSERT_EQ(kUsbType, power_status.ports[0].type);
    EXPECT_EQ(PowerSupplyProperties_ExternalPower_USB,
              power_status.external_power);
  }
}

// Tests that when multiple line power sources are reported (e.g. because both
// the PD and ACPI drivers are present), powerd favors the non-Mains source.
TEST_F(PowerSupplyTest, MultipleLinePowerSources) {
  const char kId1[] = "line1";
  const base::FilePath kDir1 = temp_dir_.GetPath().Append(kId1);
  ASSERT_TRUE(base::CreateDirectory(kDir1));
  WriteValue(kDir1, "type", kMainsType);
  WriteValue(kDir1, "online", "1");
  WriteValue(kDir1, "status", kCharging);

  const char kId2[] = "line2";
  const base::FilePath kDir2 = temp_dir_.GetPath().Append(kId2);
  ASSERT_TRUE(base::CreateDirectory(kDir2));
  WriteValue(kDir2, "type", kUsbPdDrpType);
  WriteValue(kDir2, "online", "1");
  WriteValue(kDir2, "status", kCharging);

  Init();
  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC, status.external_power);
  EXPECT_EQ(kId2, status.external_power_source_id);

  // base::FileEnumerator reads directory entries in an arbitrary but usually
  // stable order. Swap the supplies' roles to make sure that we do the right
  // thing when we see them in the opposite order.
  WriteValue(kDir1, "type", kUsbPdDrpType);
  WriteValue(kDir2, "type", kMainsType);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC, status.external_power);
  EXPECT_EQ(kId1, status.external_power_source_id);
}

TEST_F(PowerSupplyTest, DualRolePowerSources) {
  // Delete the AC power supply and report two line power sources, both
  // initially offline.
  WriteDefaultValues(PowerSource::BATTERY);
  base::DeletePathRecursively(ac_dir_);

  const char kLine1Id[] = "line1";
  const char kLine1Manufacturer[] = "04fe";
  const char kLine1ModelName[] = "0256";
  const base::FilePath line1_dir = temp_dir_.GetPath().Append(kLine1Id);
  ASSERT_TRUE(base::CreateDirectory(line1_dir));
  WriteValue(line1_dir, "type", kUsbType);
  WriteValue(line1_dir, "online", "0");
  WriteValue(line1_dir, "status", kNotCharging);
  WriteDoubleValue(line1_dir, "current_max", 0.0);
  WriteDoubleValue(line1_dir, "voltage_max_design", 0.0);
  WriteValue(line1_dir, "manufacturer", kLine1Manufacturer);
  WriteValue(line1_dir, "model_name", kLine1ModelName);

  const char kLine2Id[] = "line2";
  const char kLine2Manufacturer[] = "587b";
  const char kLine2ModelName[] = "3402";
  const base::FilePath line2_dir = temp_dir_.GetPath().Append(kLine2Id);
  ASSERT_TRUE(base::CreateDirectory(line2_dir));
  WriteValue(line2_dir, "type", kUnknownType);
  WriteValue(line2_dir, "online", "0");
  WriteValue(line2_dir, "status", kNotCharging);
  WriteDoubleValue(line2_dir, "current_max", 0.0);
  WriteDoubleValue(line2_dir, "voltage_max_design", 0.0);
  WriteValue(line2_dir, "manufacturer", kLine2Manufacturer);
  WriteValue(line2_dir, "model_name", kLine2ModelName);

  // Set the minimum power for being classified as an AC charger.
  const double kCurrentMax = 2.0;
  const double kVoltageMax = 12.0;
  prefs_.SetDouble(kUsbMinAcWattsPref, kCurrentMax * kVoltageMax);

  Init();
  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_FALSE(status.line_power_on);
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_DISCONNECTED,
            status.external_power);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_DISCHARGING,
            status.battery_state);
  ASSERT_EQ(2u, status.ports.size());
  EXPECT_EQ(kLine1Id, status.ports[0].id);
  EXPECT_EQ(Role::NONE, status.ports[0].role);
  EXPECT_EQ(kUsbType, status.ports[0].type);
  EXPECT_EQ(kLine2Id, status.ports[1].id);
  EXPECT_EQ(Role::NONE, status.ports[1].role);
  EXPECT_EQ(kUnknownType, status.ports[1].type);
  EXPECT_EQ("", status.external_power_source_id);
  EXPECT_TRUE(status.supports_dual_role_devices);
  EXPECT_DOUBLE_EQ(kCurrentMax * kVoltageMax,
                   status.preferred_minimum_external_power);

  // Start charging from the first power source at a high level.
  WriteValue(line1_dir, "type", kUsbPdDrpType);
  WriteValue(line1_dir, "online", "1");
  WriteValue(line1_dir, "status", kCharging);
  WriteDoubleValue(line1_dir, "current_max", kCurrentMax);
  WriteDoubleValue(line1_dir, "voltage_max_design", kVoltageMax);
  WriteValue(battery_dir_, "status", kCharging);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_TRUE(status.line_power_on);
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC, status.external_power);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_FULL, status.battery_state);
  ASSERT_EQ(2u, status.ports.size());
  EXPECT_EQ(kLine1Id, status.ports[0].id);
  EXPECT_EQ(Role::DUAL_ROLE, status.ports[0].role);
  EXPECT_EQ(kUsbPdDrpType, status.ports[0].type);
  EXPECT_EQ(kLine1Manufacturer, status.ports[0].manufacturer_id);
  EXPECT_EQ(kLine1ModelName, status.ports[0].model_id);
  EXPECT_EQ(kCurrentMax * kVoltageMax, status.ports[0].max_power);
  EXPECT_FALSE(status.ports[0].active_by_default);
  EXPECT_EQ(kLine2Id, status.ports[1].id);
  EXPECT_EQ(Role::NONE, status.ports[1].role);
  EXPECT_EQ(kUnknownType, status.ports[1].type);
  EXPECT_EQ(kLine1Id, status.external_power_source_id);
  EXPECT_TRUE(status.supports_dual_role_devices);
  EXPECT_DOUBLE_EQ(kCurrentMax * kVoltageMax,
                   status.preferred_minimum_external_power);

  // Disconnect the first power source and start charging from the second one at
  // a low power.
  WriteValue(line1_dir, "type", kUsbType);
  WriteValue(line1_dir, "online", "0");
  WriteValue(line1_dir, "status", kNotCharging);
  WriteValue(line2_dir, "type", kUsbPdDrpType);
  WriteValue(line2_dir, "online", "1");
  WriteValue(line2_dir, "status", kCharging);
  const double kCurrentFactor = 0.5;
  WriteDoubleValue(line2_dir, "current_max", kCurrentMax * kCurrentFactor);
  WriteDoubleValue(line2_dir, "voltage_max_design", kVoltageMax);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_TRUE(status.line_power_on);
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_USB, status.external_power);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_FULL, status.battery_state);
  ASSERT_EQ(2u, status.ports.size());
  EXPECT_EQ(kLine1Id, status.ports[0].id);
  EXPECT_EQ(Role::NONE, status.ports[0].role);
  EXPECT_EQ(kUsbType, status.ports[0].type);
  EXPECT_EQ(kLine2Id, status.ports[1].id);
  EXPECT_EQ(Role::DUAL_ROLE, status.ports[1].role);
  EXPECT_EQ(kUsbPdDrpType, status.ports[1].type);
  EXPECT_EQ(kLine2Manufacturer, status.ports[1].manufacturer_id);
  EXPECT_EQ(kLine2ModelName, status.ports[1].model_id);
  EXPECT_EQ(kCurrentMax * kCurrentFactor * kVoltageMax,
            status.ports[1].max_power);
  EXPECT_FALSE(status.ports[1].active_by_default);
  EXPECT_EQ(kLine2Id, status.external_power_source_id);

  // Now discharge from the first power source (while still charging from the
  // second one) and check that it's still listed as a connected source but not
  // reported as active.
  WriteValue(line1_dir, "type", kUsbPdDrpType);
  WriteValue(line1_dir, "online", "1");
  WriteValue(line1_dir, "status", kDischarging);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_TRUE(status.line_power_on);
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_USB, status.external_power);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_FULL, status.battery_state);
  ASSERT_EQ(2u, status.ports.size());
  EXPECT_EQ(kLine1Id, status.ports[0].id);
  EXPECT_EQ(Role::DUAL_ROLE, status.ports[0].role);
  EXPECT_EQ(kUsbPdDrpType, status.ports[0].type);
  EXPECT_EQ(kLine1Manufacturer, status.ports[0].manufacturer_id);
  EXPECT_EQ(kLine1ModelName, status.ports[0].model_id);
  EXPECT_EQ(kCurrentMax * kVoltageMax, status.ports[0].max_power);
  EXPECT_FALSE(status.ports[0].active_by_default);
  EXPECT_EQ(kLine2Id, status.ports[1].id);
  EXPECT_EQ(Role::DUAL_ROLE, status.ports[1].role);
  EXPECT_EQ(kUsbPdDrpType, status.ports[1].type);
  EXPECT_EQ(kLine2Manufacturer, status.ports[1].manufacturer_id);
  EXPECT_EQ(kLine2ModelName, status.ports[1].model_id);
  EXPECT_EQ(kCurrentMax * kCurrentFactor * kVoltageMax,
            status.ports[1].max_power);
  EXPECT_FALSE(status.ports[1].active_by_default);
  EXPECT_EQ(kLine2Id, status.external_power_source_id);

  // Request switching to the first power source.
  EXPECT_TRUE(CallSetPowerSource(kLine1Id));
  std::string value;
  EXPECT_TRUE(base::ReadFileToString(
      line1_dir.Append(PowerSupply::kChargeControlLimitMaxFile), &value));
  EXPECT_EQ("0", value);

  // Now switch to the second one.
  EXPECT_TRUE(CallSetPowerSource(kLine2Id));
  EXPECT_TRUE(base::ReadFileToString(
      line2_dir.Append(PowerSupply::kChargeControlLimitMaxFile), &value));
  EXPECT_EQ("0", value);

  // Passing an empty ID should result in -1 getting written to the active power
  // source's limit file (resulting in a switch to the battery).
  EXPECT_TRUE(CallSetPowerSource(""));
  EXPECT_TRUE(base::ReadFileToString(
      line2_dir.Append(PowerSupply::kChargeControlLimitMaxFile), &value));
  EXPECT_EQ("-1", value);

  // Ignore invalid IDs.
  EXPECT_FALSE(CallSetPowerSource("bogus"));
  EXPECT_FALSE(CallSetPowerSource("."));
  EXPECT_FALSE(CallSetPowerSource(".."));
  EXPECT_FALSE(CallSetPowerSource("../"));
  EXPECT_FALSE(CallSetPowerSource(line1_dir.value()));

  // If the kernel reports a dedicated charger by using the "Mains" type rather
  // than "USB_PD_DRP", powerd should report it as being active by default.
  WriteValue(line2_dir, "type", kMainsType);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_USB, status.external_power);
  ASSERT_EQ(2u, status.ports.size());
  EXPECT_EQ(kLine1Id, status.ports[0].id);
  EXPECT_EQ(Role::DUAL_ROLE, status.ports[0].role);
  EXPECT_EQ(kUsbPdDrpType, status.ports[0].type);
  EXPECT_EQ(kLine2Id, status.ports[1].id);
  EXPECT_EQ(Role::DEDICATED_SOURCE, status.ports[1].role);
  EXPECT_EQ(kMainsType, status.ports[1].type);
  EXPECT_TRUE(status.ports[1].active_by_default);
  EXPECT_EQ(kLine2Id, status.external_power_source_id);

  // If the kernel reports a USB charger of any type that is not "USB_PD_DRP"
  // powerd should report it as being active by default.
  const char* const kUsbTypes[] = {
      "USB", "USB_DCP", "USB_CDP", "USB_ACA", "USB_C", "USB_PD",
  };
  for (const char* kType : kUsbTypes) {
    SCOPED_TRACE(kType);
    WriteValue(line2_dir, "type", kType);
    ASSERT_TRUE(UpdateStatus(&status));
    EXPECT_EQ(PowerSupplyProperties_ExternalPower_USB, status.external_power);
    ASSERT_EQ(2u, status.ports.size());
    EXPECT_EQ(kLine2Id, status.ports[1].id);
    EXPECT_EQ(Role::DEDICATED_SOURCE, status.ports[1].role);
    EXPECT_TRUE(status.ports[1].active_by_default);
    EXPECT_EQ(kType, status.ports[1].type);
    EXPECT_EQ(kLine2Id, status.external_power_source_id);
  }

  // The maximum power should be checked even for dedicated chargers.
  WriteDoubleValue(line2_dir, "current_max", kCurrentMax);
  WriteDoubleValue(line2_dir, "voltage_max_design", kVoltageMax);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC, status.external_power);
  ASSERT_EQ(2u, status.ports.size());
  EXPECT_EQ(Role::DEDICATED_SOURCE, status.ports[1].role);
  EXPECT_TRUE(status.ports[1].active_by_default);
  EXPECT_EQ(kLine2Id, status.external_power_source_id);

  // A maximum power of 0 watts should be disregarded.
  WriteDoubleValue(line2_dir, "current_max", 0.0);
  WriteDoubleValue(line2_dir, "voltage_max_design", 0.0);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC, status.external_power);
  ASSERT_EQ(2u, status.ports.size());
  EXPECT_EQ(Role::DEDICATED_SOURCE, status.ports[1].role);
  EXPECT_TRUE(status.ports[1].active_by_default);
  EXPECT_EQ(kLine2Id, status.external_power_source_id);

  // USB_PD_DRP should report as dual role.
  WriteValue(line2_dir, "type", "USB_PD_DRP");
  ASSERT_TRUE(UpdateStatus(&status));
  ASSERT_EQ(Role::DUAL_ROLE, status.ports[1].role);

  // USB should report as dual role if usb_type selects PD_DRP.
  WriteValue(line2_dir, "type", "USB");
  WriteValue(line2_dir, "usb_type",
             "Unknown SDP DCP CDP C PD [PD_DRP] BrickID");
  ASSERT_TRUE(UpdateStatus(&status));
  ASSERT_EQ(Role::DUAL_ROLE, status.ports[1].role);

  // USB should not report as dual role if usb_type is craaaazy.
  for (const char* const kType : kInvalidUsbTypeValues) {
    SCOPED_TRACE(kType);
    WriteValue(line2_dir, "usb_type", kType);
    ASSERT_TRUE(UpdateStatus(&status));
    ASSERT_EQ(Role::DEDICATED_SOURCE, status.ports[1].role);
  }
}

TEST_F(PowerSupplyTest, ChargingPortNames) {
  // Write a pref describing two charging ports and say that we're charging from
  // the first one. PowerSupply will sort the ports by name.
  const char kSecondName[] = "port2";
  prefs_.SetString(
      kChargingPortsPref,
      base::StringPrintf("%s LEFT_FRONT\n%s RIGHT_BACK",
                         ac_dir_.BaseName().value().c_str(), kSecondName));
  WriteDefaultValues(PowerSource::AC);

  // Connect a second, idle power source.
  const base::FilePath kSecondDir = temp_dir_.GetPath().Append(kSecondName);
  ASSERT_TRUE(base::CreateDirectory(kSecondDir));
  WriteValue(kSecondDir, "online", "1");
  WriteValue(kSecondDir, "type", kUsbType);
  WriteValue(kSecondDir, "status", kNotCharging);

  // Add a third port that isn't described by the pref.
  const char kThirdName[] = "port3";
  const base::FilePath kThirdDir = temp_dir_.GetPath().Append(kThirdName);
  ASSERT_TRUE(base::CreateDirectory(kThirdDir));
  WriteValue(kThirdDir, "online", "1");
  WriteValue(kThirdDir, "type", kUsbType);
  WriteValue(kThirdDir, "status", kNotCharging);

  // Check that all three port's locations are reported correctly.
  Init();
  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  ASSERT_EQ(3u, status.ports.size());
  EXPECT_EQ(PowerSupplyProperties_PowerSource_Port_LEFT_FRONT,
            status.ports[0].location);
  EXPECT_EQ(PowerSupplyProperties_PowerSource_Port_RIGHT_BACK,
            status.ports[1].location);
  EXPECT_EQ(PowerSupplyProperties_PowerSource_Port_UNKNOWN,
            status.ports[2].location);
}

TEST_F(PowerSupplyTest, IgnorePeripherals) {
  // Power supplies corresponding to external peripherals (i.e. with a "scope"
  // of "Device") should be ignored.
  WriteDefaultValues(PowerSource::AC);
  WriteValue(ac_dir_, "scope", "Device");
  WriteValue(battery_dir_, "status", kDischarging);

  Init();
  PowerStatus power_status;
  ASSERT_TRUE(UpdateStatus(&power_status));
  EXPECT_FALSE(power_status.line_power_on);
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_DISCONNECTED,
            power_status.external_power);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_DISCHARGING,
            power_status.battery_state);
}

// Test battery reporting energy instead of charge.
TEST_F(PowerSupplyTest, EnergyDischarging) {
  WriteDefaultValues(PowerSource::BATTERY);
  base::DeleteFile(battery_dir_.Append("charge_full"));
  base::DeleteFile(battery_dir_.Append("charge_full_design"));
  base::DeleteFile(battery_dir_.Append("charge_now"));
  base::DeleteFile(battery_dir_.Append("current_now"));
  base::DeleteFile(battery_dir_.Append("voltage_min_design"));

  const double kNominalVoltage = kVoltage + 1.0;
  const double kChargeFull = 2.40;
  const double kChargeNow = 1.80;
  const double kCurrentNow = 0.20;
  // Use nominal voltage when calculating remaining battery charge and the
  // current voltage when calculating current.
  const double kEnergyFull = kChargeFull * kNominalVoltage;
  const double kEnergyNow = kChargeNow * kNominalVoltage;
  const double kPowerNow = kCurrentNow * kVoltage;
  const double kEnergyRate = kCurrentNow * kVoltage;
  const double kPercentage = 100.0 * kChargeNow / kChargeFull;
  WriteDoubleValue(battery_dir_, "energy_full", kEnergyFull);
  WriteDoubleValue(battery_dir_, "energy_full_design", kEnergyFull);
  WriteDoubleValue(battery_dir_, "energy_now", kEnergyNow);
  WriteDoubleValue(battery_dir_, "power_now", kPowerNow);
  WriteDoubleValue(battery_dir_, "voltage_min_design", kNominalVoltage);

  Init();
  PowerStatus power_status;
  ASSERT_TRUE(UpdateStatus(&power_status));
  EXPECT_FALSE(power_status.line_power_on);
  EXPECT_TRUE(power_status.battery_is_present);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_DISCHARGING,
            power_status.battery_state);
  EXPECT_DOUBLE_EQ(kEnergyNow, power_status.battery_energy);
  EXPECT_DOUBLE_EQ(kEnergyRate, power_status.battery_energy_rate);
  EXPECT_DOUBLE_EQ(kPercentage, power_status.battery_percentage);

  // Charge values should be computed.
  EXPECT_DOUBLE_EQ(kChargeFull, power_status.battery_charge_full);
  EXPECT_DOUBLE_EQ(kChargeFull, power_status.battery_charge_full_design);
  EXPECT_DOUBLE_EQ(kChargeNow, power_status.battery_charge);
  EXPECT_DOUBLE_EQ(kCurrentNow, power_status.battery_current);

  WriteDoubleValue(battery_dir_, "power_now", -kPowerNow);
  ASSERT_TRUE(UpdateStatus(&power_status));
  EXPECT_EQ(PowerSupplyProperties_BatteryState_DISCHARGING,
            power_status.battery_state);
  EXPECT_DOUBLE_EQ(kEnergyNow, power_status.battery_energy);
  EXPECT_DOUBLE_EQ(kEnergyRate, power_status.battery_energy_rate);
  EXPECT_DOUBLE_EQ(kPercentage, power_status.battery_percentage);
}

TEST_F(PowerSupplyTest, PollDelays) {
  WriteDefaultValues(PowerSource::AC);

  const base::TimeDelta kPollDelay = base::Seconds(30);
  const base::TimeDelta kPollDelayInitial = base::Seconds(1);
  const base::TimeDelta kStartupDelay = base::Seconds(6);
  const base::TimeDelta kACDelay = base::Seconds(7);
  const base::TimeDelta kBatteryDelay = base::Seconds(8);
  const base::TimeDelta kResumeDelay = base::Seconds(10);
  const base::TimeDelta kSlack = PowerSupply::kBatteryStabilizedSlack;

  prefs_.SetInt64(kBatteryPollIntervalPref, kPollDelay.InMilliseconds());
  prefs_.SetInt64(kBatteryPollIntervalInitialPref,
                  kPollDelayInitial.InMilliseconds());
  prefs_.SetInt64(kBatteryStabilizedAfterStartupMsPref,
                  kStartupDelay.InMilliseconds());
  prefs_.SetInt64(kBatteryStabilizedAfterLinePowerConnectedMsPref,
                  kACDelay.InMilliseconds());
  prefs_.SetInt64(kBatteryStabilizedAfterLinePowerDisconnectedMsPref,
                  kBatteryDelay.InMilliseconds());
  prefs_.SetInt64(kBatteryStabilizedAfterResumeMsPref,
                  kResumeDelay.InMilliseconds());

  // Set max sample to 3 for simplicity.
  prefs_.SetInt64(kMaxCurrentSamplesPref, 3);

  base::TimeTicks current_time = kStartTime;
  Init();

  // The battery times should be reported as "calculating" just after
  // initialization.
  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_TRUE(status.line_power_on);
  EXPECT_TRUE(status.is_calculating_battery_time);
  EXPECT_EQ((kStartupDelay + kSlack).InMilliseconds(),
            test_api_->current_poll_delay().InMilliseconds());

  // After enough time has elapsed, the battery times should not be reported
  // until the we have |kMaxCurrentSamplesPref| samples.
  current_time += kStartupDelay + kSlack;
  test_api_->SetCurrentTime(current_time);
  ASSERT_TRUE(test_api_->TriggerPollTimeout());
  status = power_supply_->GetPowerStatus();
  EXPECT_TRUE(status.line_power_on);
  EXPECT_TRUE(status.is_calculating_battery_time);
  EXPECT_EQ(kPollDelayInitial.InMilliseconds(),
            test_api_->current_poll_delay().InMilliseconds());
  EXPECT_TRUE(status.is_calculating_battery_time);

  // 2nd sample
  current_time += kPollDelayInitial;
  test_api_->SetCurrentTime(current_time);
  ASSERT_TRUE(test_api_->TriggerPollTimeout());
  status = power_supply_->GetPowerStatus();
  EXPECT_EQ(kPollDelayInitial.InMilliseconds(),
            test_api_->current_poll_delay().InMilliseconds());
  EXPECT_TRUE(status.is_calculating_battery_time);

  // 3rd sample. We should start reporting when the number of samples is
  // equal to |kMaxCurrentSamplesPref|.
  current_time += kPollDelayInitial;
  test_api_->SetCurrentTime(current_time);
  ASSERT_TRUE(test_api_->TriggerPollTimeout());
  status = power_supply_->GetPowerStatus();
  EXPECT_EQ(kPollDelay.InMilliseconds(),
            test_api_->current_poll_delay().InMilliseconds());
  EXPECT_FALSE(status.is_calculating_battery_time);

  // Polling should stop when the system is about to suspend.
  power_supply_->SetSuspended(true);
  EXPECT_EQ(0, test_api_->current_poll_delay().InMilliseconds());

  // After resuming, the status should be updated immediately and the
  // battery times should be reported as "calculating" again.
  current_time += base::Seconds(120);
  test_api_->SetCurrentTime(current_time);
  UpdatePowerSourceAndBatteryStatus(PowerSource::BATTERY, kMainsType,
                                    kDischarging);
  power_supply_->SetSuspended(false);
  status = power_supply_->GetPowerStatus();
  EXPECT_FALSE(status.line_power_on);
  EXPECT_TRUE(status.is_calculating_battery_time);
  EXPECT_EQ((kResumeDelay + kSlack).InMilliseconds(),
            test_api_->current_poll_delay().InMilliseconds());

  // Check that the polling starts after |kResumeDelay| + |kSlack| and the
  // updated time returns after having |kMaxCurrentSamplesPref| samples.
  current_time += kResumeDelay + kSlack;
  test_api_->SetCurrentTime(current_time);
  ASSERT_TRUE(test_api_->TriggerPollTimeout());
  status = power_supply_->GetPowerStatus();
  EXPECT_FALSE(status.line_power_on);
  EXPECT_TRUE(status.is_calculating_battery_time);

  // 2nd sample
  current_time += kPollDelayInitial;
  test_api_->SetCurrentTime(current_time);
  ASSERT_TRUE(test_api_->TriggerPollTimeout());
  status = power_supply_->GetPowerStatus();
  EXPECT_TRUE(status.is_calculating_battery_time);

  // 3rd sample. We should start reporting estimates now.
  current_time += kPollDelayInitial;
  test_api_->SetCurrentTime(current_time);
  ASSERT_TRUE(test_api_->TriggerPollTimeout());
  status = power_supply_->GetPowerStatus();
  EXPECT_FALSE(status.is_calculating_battery_time);

  // Connect AC, report a udev event, and check that the status is updated.
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kMainsType, kCharging);
  SendUdevEvent(kUdevSubsystemAC);
  status = power_supply_->GetPowerStatus();
  EXPECT_TRUE(status.line_power_on);
  EXPECT_TRUE(status.is_calculating_battery_time);
  EXPECT_EQ((kACDelay + kSlack).InMilliseconds(),
            test_api_->current_poll_delay().InMilliseconds());

  // After the delay, estimates should be made again after after having
  // |kMaxCurrentSamplesPref| samples because we clear previous data as
  // AC power can be vary a lot between different chargers.
  current_time += kACDelay + kSlack;
  test_api_->SetCurrentTime(current_time);
  ASSERT_TRUE(test_api_->TriggerPollTimeout());
  status = power_supply_->GetPowerStatus();
  EXPECT_TRUE(status.line_power_on);
  EXPECT_TRUE(status.is_calculating_battery_time);

  // 2nd sample
  current_time += kPollDelayInitial;
  test_api_->SetCurrentTime(current_time);
  ASSERT_TRUE(test_api_->TriggerPollTimeout());
  status = power_supply_->GetPowerStatus();
  EXPECT_TRUE(status.is_calculating_battery_time);

  // 3rd sample. We should start reporting estimates now.
  current_time += kPollDelayInitial;
  test_api_->SetCurrentTime(current_time);
  ASSERT_TRUE(test_api_->TriggerPollTimeout());
  status = power_supply_->GetPowerStatus();
  EXPECT_FALSE(status.is_calculating_battery_time);

  // Now test the delay when going back to battery power.
  UpdatePowerSourceAndBatteryStatus(PowerSource::BATTERY, kMainsType,
                                    kDischarging);
  SendUdevEvent(kUdevSubsystemBAT0);
  status = power_supply_->GetPowerStatus();
  EXPECT_FALSE(status.line_power_on);
  EXPECT_TRUE(status.is_calculating_battery_time);
  EXPECT_EQ((kBatteryDelay + kSlack).InMilliseconds(),
            test_api_->current_poll_delay().InMilliseconds());

  // After the delay, estimates should be made again on the first sampling
  // because switching from AC to battery power won't clear previous data.
  current_time += kBatteryDelay + kSlack;
  test_api_->SetCurrentTime(current_time);
  ASSERT_TRUE(test_api_->TriggerPollTimeout());
  status = power_supply_->GetPowerStatus();
  EXPECT_FALSE(status.line_power_on);
  EXPECT_FALSE(status.is_calculating_battery_time);
}

TEST_F(PowerSupplyTest, UpdateBatteryTimeEstimates) {
  // Start out with the battery 50% full and an unset current.
  WriteDefaultValues(PowerSource::AC);
  UpdateChargeAndCurrent(0.5, 0.0);
  prefs_.SetDouble(kPowerSupplyFullFactorPref, 1.0);
  // To simplify this test, average just the last two samples.
  prefs_.SetInt64(kMaxCurrentSamplesPref, 2);
  Init();

  EXPECT_EQ(MakeEstimateString(true, 0, 0), UpdateAndGetEstimateString());

  // Set the current such that it'll take an hour to charge fully and
  // advance the clock so the current will be used.
  UpdateChargeAndCurrent(0.5, 0.5);
  SetStabilizedTime();

  // First update should report as "calculating" number of sample is less than
  // |kMaxCurrentSamplesPref|.
  EXPECT_EQ(MakeEstimateString(true, 0, 0), UpdateAndGetEstimateString());
  EXPECT_EQ(MakeEstimateString(false, 0, 3600), UpdateAndGetEstimateString());

  // Let half an hour pass and report that the battery is 75% full.
  test_api_->AdvanceTime(base::Minutes(30));
  UpdateChargeAndCurrent(0.75, 0.5);
  EXPECT_EQ(MakeEstimateString(false, 0, 1800), UpdateAndGetEstimateString());

  // After a current reading of 1.0, the averaged current should be (0.5 + 1.0)
  // / 2 = 0.75. The remaining 0.25 of charge to get to 100% should take twenty
  // minutes.
  UpdateChargeAndCurrent(0.75, 1.0);
  EXPECT_EQ(MakeEstimateString(false, 0, 1200), UpdateAndGetEstimateString());

  // Fifteen minutes later, set the current to 0.25 (giving an average of (1.0 +
  // 0.25) / 2 = 0.625) and report an increased charge. There should be 0.125 /
  // 0.625 * 3600 = 720 seconds until the battery is full.
  test_api_->AdvanceTime(base::Minutes(15));
  UpdateChargeAndCurrent(0.875, 0.25);
  EXPECT_EQ(MakeEstimateString(false, 0, 720), UpdateAndGetEstimateString());

  // Disconnect the charger and report an immediate drop in charge and
  // current. The current shouldn't be used yet.
  UpdatePowerSourceAndBatteryStatus(PowerSource::BATTERY, kMainsType,
                                    kDischarging);
  UpdateChargeAndCurrent(0.5, -0.5);
  EXPECT_EQ(MakeEstimateString(true, 0, 0), UpdateAndGetEstimateString());

  // After the current has had time to stabilize, the average should be
  // reset and the time-to-empty should be estimated after having
  // |kMaxCurrentSamplesPref| samples.
  SetStabilizedTime();
  EXPECT_EQ(MakeEstimateString(true, 0, 0), UpdateAndGetEstimateString());
  EXPECT_EQ(MakeEstimateString(false, 3600, 0), UpdateAndGetEstimateString());

  // Thirty minutes later, decrease the charge and report a significantly
  // higher current.
  test_api_->AdvanceTime(base::Minutes(30));
  UpdateChargeAndCurrent(0.25, -1.5);
  EXPECT_EQ(MakeEstimateString(false, 900, 0), UpdateAndGetEstimateString());

  // A current report of 0 should be ignored.
  UpdateChargeAndCurrent(0.25, 0.0);
  EXPECT_EQ(MakeEstimateString(false, 900, 0), UpdateAndGetEstimateString());

  // Suspend, change the current, and resume. The battery time should be
  // reported as "calculating".
  power_supply_->SetSuspended(true);
  UpdateChargeAndCurrent(0.25, -2.5);
  test_api_->AdvanceTime(base::Seconds(8));
  power_supply_->SetSuspended(false);
  EXPECT_EQ(MakeEstimateString(true, 0, 0), UpdateAndGetEstimateString());

  // Wait for the current to stabilize. The last valid sample (-1.5) should be
  // averaged with the latest one.
  SetStabilizedTime();
  EXPECT_EQ(MakeEstimateString(false, 450, 0), UpdateAndGetEstimateString());

  // Switch back to line power. Since the current delivered on line power can
  // vary greatly, the previous sample should be discarded.
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kMainsType, kCharging);
  UpdateChargeAndCurrent(0.5, 0.25);
  EXPECT_EQ(MakeEstimateString(true, 0, 0), UpdateAndGetEstimateString());
  SetStabilizedTime();
  EXPECT_EQ(MakeEstimateString(true, 0, 0), UpdateAndGetEstimateString());
  EXPECT_EQ(MakeEstimateString(false, 0, 7200), UpdateAndGetEstimateString());

  // Go back to battery and check that the previous on-battery current sample
  // (-2.5) is included in the average.
  UpdatePowerSourceAndBatteryStatus(PowerSource::BATTERY, kMainsType,
                                    kDischarging);
  UpdateChargeAndCurrent(0.5, -1.5);
  EXPECT_EQ(MakeEstimateString(true, 0, 0), UpdateAndGetEstimateString());
  SetStabilizedTime();
  EXPECT_EQ(MakeEstimateString(false, 900, 0), UpdateAndGetEstimateString());
}

TEST_F(PowerSupplyTest, UsbBatteryTimeEstimates) {
  WriteDefaultValues(PowerSource::AC);
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kUsbType, kCharging);
  UpdateChargeAndCurrent(0.5, 1.0);
  prefs_.SetDouble(kPowerSupplyFullFactorPref, 1.0);
  prefs_.SetInt64(kMaxCurrentSamplesPref, 2);
  Init();

  // Start out charging on USB power.
  SetStabilizedTime();
  EXPECT_EQ(MakeEstimateString(true, 0, 0), UpdateAndGetEstimateString());
  EXPECT_EQ(MakeEstimateString(false, 0, 1800), UpdateAndGetEstimateString());

  // Now discharge while still on USB. Since the averaged charge is still
  // positive, we should avoid providing a time-to-empty estimate.
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kUsbType, kDischarging);
  UpdateChargeAndCurrent(0.5, -0.5);
  EXPECT_EQ(MakeEstimateString(false, -1, 0), UpdateAndGetEstimateString());

  // After another sample brings the average current to -1.0,
  // time-to-empty/shutdown should be calculated.
  UpdateChargeAndCurrent(0.5, -1.5);
  EXPECT_EQ(MakeEstimateString(false, 1800, 0), UpdateAndGetEstimateString());

  // Now start charging. Since the average current is still negative, we should
  // avoid computing time-to-full.
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kUsbType, kCharging);
  UpdateChargeAndCurrent(0.5, 0.5);
  EXPECT_EQ(MakeEstimateString(false, 0, -1), UpdateAndGetEstimateString());

  // Switch to battery power.
  UpdatePowerSourceAndBatteryStatus(PowerSource::BATTERY, kMainsType,
                                    kDischarging);
  UpdateChargeAndCurrent(0.5, -1.0);
  EXPECT_EQ(MakeEstimateString(true, 0, 0), UpdateAndGetEstimateString());
  SetStabilizedTime();
  EXPECT_EQ(MakeEstimateString(true, 0, 0), UpdateAndGetEstimateString());
  EXPECT_EQ(MakeEstimateString(false, 1800, 0), UpdateAndGetEstimateString());

  // Go back to USB.
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kMainsType, kCharging);
  UpdateChargeAndCurrent(0.5, 1.0);
  EXPECT_EQ(MakeEstimateString(true, 0, 0), UpdateAndGetEstimateString());

  // Since different USB chargers can provide different current, the previous
  // on-line-power average should be thrown out.
  SetStabilizedTime();
  EXPECT_EQ(MakeEstimateString(true, 0, 0), UpdateAndGetEstimateString());
  EXPECT_EQ(MakeEstimateString(false, 0, 1800), UpdateAndGetEstimateString());
}

TEST_F(PowerSupplyTest, BatteryTimeEstimatesWithZeroCurrent) {
  WriteDefaultValues(PowerSource::AC);
  UpdateChargeAndCurrent(0.5, 0.1 * kEpsilon);
  prefs_.SetInt64(kMaxCurrentSamplesPref, 1);
  Init();

  // When the only available current readings are close to 0 (which would
  // result in very large time estimates), -1 estimates should be provided
  // instead.
  SetStabilizedTime();
  EXPECT_EQ(MakeEstimateString(false, 0, -1), UpdateAndGetEstimateString());

  UpdatePowerSourceAndBatteryStatus(PowerSource::BATTERY, kMainsType,
                                    kDischarging);
  EXPECT_EQ(MakeEstimateString(true, 0, 0), UpdateAndGetEstimateString());
  SetStabilizedTime();
  EXPECT_EQ(MakeEstimateString(false, -1, 0), UpdateAndGetEstimateString());
}

TEST_F(PowerSupplyTest, FullFactor) {
  // When the battery has reached the full factor, it should be reported as
  // fully charged regardless of the current.
  WriteDefaultValues(PowerSource::AC);
  UpdateChargeAndCurrent(kFullFactor, 1.0);
  Init();
  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(PowerSupplyProperties_BatteryState_FULL, status.battery_state);
  EXPECT_DOUBLE_EQ(100.0, status.display_battery_percentage);

  // It should stay full when the current goes to zero.
  UpdateChargeAndCurrent(kFullFactor, 0.0);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(PowerSupplyProperties_BatteryState_FULL, status.battery_state);
  EXPECT_DOUBLE_EQ(100.0, status.display_battery_percentage);
}

TEST_F(PowerSupplyTest, DisplayBatteryPercent) {
  static const double kShutdownPercent = 5.0;
  prefs_.SetDouble(kLowBatteryShutdownPercentPref, kShutdownPercent);

  // Start out with a full battery on AC power.
  WriteDefaultValues(PowerSource::AC);
  UpdateChargeAndCurrent(1.0, 0.0);
  Init();

  // 100% should be reported both on AC and battery power.
  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(100.0, status.display_battery_percentage);
  UpdatePowerSourceAndBatteryStatus(PowerSource::BATTERY, kMainsType,
                                    kDischarging);
  UpdateChargeAndCurrent(1.0, -1.0);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(100.0, status.display_battery_percentage);

  // Decrease the battery charge, but keep it above the full-factor-derived
  // "full" threshold. Batteries sometimes report a lower charge as soon
  // as line power has been disconnected.
  const double kFullCharge = kFullFactor;
  UpdateChargeAndCurrent(kFullCharge, 0.0);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(100.0, status.display_battery_percentage);

  // Lower charges should be scaled.
  const double kLowerCharge = 0.92;
  UpdateChargeAndCurrent(kLowerCharge, 0.0);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(100.0 * (100.0 * kLowerCharge - kShutdownPercent) /
                       (100.0 * kFullFactor - kShutdownPercent),
                   status.display_battery_percentage);

  // Switch to AC and check that the scaling remains the same.
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kMainsType, kCharging);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(100.0 * (100.0 * kLowerCharge - kShutdownPercent) /
                       (100.0 * kFullFactor - kShutdownPercent),
                   status.display_battery_percentage);

  UpdateChargeAndCurrent(0.85, 0.0);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(100 * (85.0 - kShutdownPercent) /
                       (100.0 * kFullFactor - kShutdownPercent),
                   status.display_battery_percentage);

  UpdateChargeAndCurrent(kShutdownPercent / 100.0, 0.0);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(0.0, status.display_battery_percentage);
}

TEST_F(PowerSupplyTest, EcDisplayBatteryPercent) {
  struct ec_response_display_soc resp;
  // |display_soc| and |shutdown_soc| are divided by 10.0 to get the
  // percentages. |full_factor| is divided by 1000.0 to get the |full_factor_|
  resp.display_soc = 1000.0;
  resp.full_factor = 970.0;
  resp.shutdown_soc = 50.0;

  ON_CALL(ec_command_factory_, DisplayStateOfChargeCommand)
      .WillByDefault([r = &resp]() {
        auto cmd = std::make_unique<MockDisplayStateOfChargeCommand>();
        cmd->Resp()->display_soc = r->display_soc;
        cmd->Resp()->full_factor = r->full_factor;
        cmd->Resp()->shutdown_soc = r->shutdown_soc;
        EXPECT_CALL(*cmd, Run(_)).WillOnce(Return(true));
        return cmd;
      });

  WriteDefaultValues(PowerSource::AC);
  UpdateChargeAndCurrent(1.0, 0.0);
  Init();
  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(100.0, status.display_battery_percentage);

  // Set a battery charge of 77% with a display battery percentage of 80%.
  UpdateChargeAndCurrent(0.77, 0.0);
  resp.display_soc = 800.0;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(80.0, status.display_battery_percentage);

  // Check that display_battery_percentage isn't updated when an error in
  // reading it from the EC occurs, causing an extreme mismatch between
  // battery_percentage and display_battery_percentage.
  resp.display_soc = 0.0;
  ASSERT_FALSE(UpdateStatus(&status));
  EXPECT_EQ(80.0, status.display_battery_percentage);
}

TEST_F(PowerSupplyTest, BadSingleBattery) {
  // Check that reading broken battery data the first time through yields
  // failure but still results in the partially-correct status being recorded.
  // At startup, powerd needs to use what it can get.
  WriteDefaultValues(PowerSource::AC);
  UpdateChargeAndCurrent(0.0, 0.0);
  WriteDoubleValue(battery_dir_, "voltage_min_design", 0.0);
  Init();

  PowerStatus status;
  EXPECT_FALSE(UpdateStatus(&status));
  EXPECT_TRUE(status.line_power_on);
  EXPECT_FALSE(status.battery_below_shutdown_threshold);
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC, status.external_power);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_NOT_PRESENT,
            status.battery_state);

  // Report a full battery.
  UpdateChargeAndCurrent(1.0, 0.0);
  WriteDoubleValue(battery_dir_, "voltage_min_design", kVoltage);
  EXPECT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(100.0, status.display_battery_percentage);

  // The update should be dropped if we see zero or negative instantaneous or
  // full charges: http://crbug.com/924869
  UpdateChargeAndCurrent(0.0, 0.0);
  EXPECT_FALSE(UpdateStatus(&status));
  EXPECT_FALSE(status.battery_below_shutdown_threshold);

  UpdateChargeAndCurrent(-0.1, 0.0);
  EXPECT_FALSE(UpdateStatus(&status));
  EXPECT_FALSE(status.battery_below_shutdown_threshold);

  UpdateChargeAndCurrent(0.5, 0.0);
  WriteDoubleValue(battery_dir_, "charge_full", 0.0);
  EXPECT_FALSE(UpdateStatus(&status));
  EXPECT_FALSE(status.battery_below_shutdown_threshold);

  WriteDoubleValue(battery_dir_, "charge_full", -0.1);
  EXPECT_FALSE(UpdateStatus(&status));
  EXPECT_FALSE(status.battery_below_shutdown_threshold);
}

TEST_F(PowerSupplyTest, BadMultipleBatteries) {
  // Start out with two batteries.
  WriteDefaultValues(PowerSource::AC);
  AddSecondBattery(kCharging);
  prefs_.SetInt64(kMultipleBatteriesPref, 1);
  Init();
  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));

  // We should tolerate one of the batteries having a zero charge.
  WriteDoubleValue(second_battery_dir_, "charge_now", 0.0);
  EXPECT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(kDefaultCharge, status.battery_charge);
  EXPECT_DOUBLE_EQ(kDefaultChargeFull + kDefaultSecondChargeFull,
                   status.battery_charge_full);

  // If the second battery reports a zero full charge, we should treat it as
  // bogus and exclude it from calculations.
  WriteDoubleValue(second_battery_dir_, "charge_now", 0.5);
  WriteDoubleValue(second_battery_dir_, "charge_full", 0.0);
  EXPECT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(kDefaultCharge, status.battery_charge);
  EXPECT_DOUBLE_EQ(kDefaultChargeFull, status.battery_charge);

  // If both batteries report a zero charge, we should assume that something is
  // wrong and reject the reading.
  WriteDoubleValue(battery_dir_, "charge_now", 0.0);
  WriteDoubleValue(second_battery_dir_, "charge_now", 0.0);
  WriteDoubleValue(second_battery_dir_, "charge_full",
                   kDefaultSecondChargeFull);
  EXPECT_FALSE(UpdateStatus(&status));
}

TEST_F(PowerSupplyTest, CheckForLowBattery) {
  const double kShutdownPercent = 5.0;
  const double kCurrent = -1.0;
  prefs_.SetDouble(kLowBatteryShutdownPercentPref, kShutdownPercent);

  WriteDefaultValues(PowerSource::BATTERY);
  UpdateChargeAndCurrent((kShutdownPercent + 1.0) / 100.0, kCurrent);
  Init();

  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_FALSE(status.battery_below_shutdown_threshold);

  UpdateChargeAndCurrent((kShutdownPercent - 1.0) / 100.0, kCurrent);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_TRUE(status.battery_below_shutdown_threshold);

  // Don't shut down when on AC power when the battery's charge isn't observed
  // to be decreasing.
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kMainsType, kDischarging);
  UpdateChargeAndCurrent((kShutdownPercent - 1.0) / 100.0, kCurrent);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_FALSE(status.battery_below_shutdown_threshold);

  // Don't shut down for other chargers in this situation, either.
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kUsbType, kDischarging);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_FALSE(status.battery_below_shutdown_threshold);

  // Test that the system shuts down while on AC power if the charge appears to
  // be falling (i.e. the charger isn't able to deliver enough current).
  SetStabilizedTime();
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kMainsType, kDischarging);
  UpdateChargeAndCurrent((kShutdownPercent - 1.0) / 100.0, kCurrent);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_FALSE(status.battery_below_shutdown_threshold);

  // After just half of the observation period has elapsed, the system should
  // still be up.
  const base::TimeDelta kObservationTime =
      PowerSupply::kObservedBatteryChargeRateMin;
  UpdateChargeAndCurrent((kShutdownPercent - 1.5) / 100.0, kCurrent);
  test_api_->AdvanceTime(kObservationTime / 2);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_FALSE(status.battery_below_shutdown_threshold);

  // If the charge is still trending downward after the full observation period
  // has elapsed, the system should shut down.
  UpdateChargeAndCurrent((kShutdownPercent - 2.0) / 100.0, kCurrent);
  test_api_->AdvanceTime(kObservationTime / 2);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_TRUE(status.battery_below_shutdown_threshold);
}

TEST_F(PowerSupplyTest, FactoryMode) {
  const double kShutdownPercent = 5.0;
  const double kCurrent = -1.0;
  prefs_.SetDouble(kLowBatteryShutdownPercentPref, kShutdownPercent);
  prefs_.SetInt64(kFactoryModePref, 1);
  WriteDefaultValues(PowerSource::BATTERY);
  Init();

  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  UpdateChargeAndCurrent((kShutdownPercent - 1.0) / 100.0, kCurrent);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_FALSE(status.battery_below_shutdown_threshold);
}

TEST_F(PowerSupplyTest, LowPowerCharger) {
  // If a charger is connected but the current is zero and the battery
  // isn't full, the battery should be reported as discharging.
  WriteDefaultValues(PowerSource::AC);
  UpdateChargeAndCurrent(0.5, 0.0);
  Init();
  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC, status.external_power);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_DISCHARGING,
            status.battery_state);

  // If the current is nonzero but the kernel-reported status is
  // "Discharging", the battery should be reported as discharging.
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kMainsType, kDischarging);
  UpdateChargeAndCurrent(0.5, 1.0);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC, status.external_power);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_DISCHARGING,
            status.battery_state);
}

TEST_F(PowerSupplyTest, ConnectedToUsb) {
  WriteDefaultValues(PowerSource::AC);
  UpdateChargeAndCurrent(0.5, 1.0);
  Init();

  // Check that the "connected to USB" status is reported for all
  // USB-related strings used by the kernel.
  PowerStatus status;
  const char* const kUsbTypes[] = {"USB", "USB_DCP", "USB_CDP", "USB_ACA"};
  for (const char* kType : kUsbTypes) {
    SCOPED_TRACE(kType);
    UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kType, kCharging);
    ASSERT_TRUE(UpdateStatus(&status));
    EXPECT_EQ(PowerSupplyProperties_BatteryState_CHARGING,
              status.battery_state);
    EXPECT_EQ(PowerSupplyProperties_ExternalPower_USB, status.external_power);
  }

  // The USB type should be reported even when the current is 0.
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kUsbType, kCharging);
  UpdateChargeAndCurrent(0.5, 0.0);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(PowerSupplyProperties_BatteryState_DISCHARGING,
            status.battery_state);
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_USB, status.external_power);
}

TEST_F(PowerSupplyTest, ShutdownPercentAffectsBatteryTime) {
  const double kShutdownPercent = 10.0;
  prefs_.SetDouble(kLowBatteryShutdownPercentPref, kShutdownPercent);
  const double kShutdownSec = 3200;
  prefs_.SetDouble(kLowBatteryShutdownTimePref, kShutdownSec);
  const double kCurrent = -1.0;

  WriteDefaultValues(PowerSource::BATTERY);
  UpdateChargeAndCurrent(0.5, kCurrent);
  prefs_.SetDouble(kPowerSupplyFullFactorPref, 1.0);
  prefs_.SetInt64(kMaxCurrentSamplesPref, 1);
  Init();
  SetStabilizedTime();

  // The reported time until shutdown should be based only on the charge that's
  // available before shutdown. Note also that the time-based shutdown threshold
  // is ignored since a percent-based threshold is set.
  const double kShutdownCharge = kShutdownPercent / 100.0 * 1.0;
  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(1800, status.battery_time_to_empty.InSeconds());
  EXPECT_EQ(roundl((0.5 - kShutdownCharge) * 3600),
            status.battery_time_to_shutdown.InSeconds());
  EXPECT_FALSE(status.battery_below_shutdown_threshold);

  // The reported time should be zero once the threshold is reached.
  UpdateChargeAndCurrent(kShutdownCharge, kCurrent);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(roundl(kShutdownCharge / 1.0 * 3600),
            status.battery_time_to_empty.InSeconds());
  EXPECT_EQ(0, status.battery_time_to_shutdown.InSeconds());
  EXPECT_TRUE(status.battery_below_shutdown_threshold);

  // It should remain zero if the threshold is passed.
  static const double kLowerCharge = kShutdownCharge / 2.0;
  UpdateChargeAndCurrent(kLowerCharge, kCurrent);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(roundl(kLowerCharge / 1.0 * 3600),
            status.battery_time_to_empty.InSeconds());
  EXPECT_EQ(0, status.battery_time_to_shutdown.InSeconds());
  EXPECT_TRUE(status.battery_below_shutdown_threshold);
}

TEST_F(PowerSupplyTest, ObservedBatteryChargeRate) {
  const int kMaxSamples = 5;
  prefs_.SetInt64(kMaxCurrentSamplesPref, kMaxSamples);
  prefs_.SetInt64(kMaxChargeSamplesPref, kMaxSamples);

  WriteDefaultValues(PowerSource::BATTERY);
  WriteDoubleValue(battery_dir_, "charge_full", 10.0);
  UpdateChargeAndCurrent(10.0, -1.0);
  prefs_.SetDouble(kPowerSupplyFullFactorPref, 1.0);
  Init();
  SetStabilizedTime();

  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(0.0, status.observed_battery_charge_rate);

  // Advance the time, but not by enough to estimate the rate.
  const base::TimeDelta kObservationTime =
      PowerSupply::kObservedBatteryChargeRateMin;
  test_api_->AdvanceTime(kObservationTime / 2);
  UpdateChargeAndCurrent(9.0, -1.0);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(0.0, status.observed_battery_charge_rate);

  // Advance the time by enough so the next reading will be a full hour from the
  // first one, indicating that the charge is dropping by 1 Ah per hour.
  test_api_->AdvanceTime(base::Hours(1) - kObservationTime / 2);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(-1.0, status.observed_battery_charge_rate);

  // Decrease the charge by 3 Ah over the next hour.
  test_api_->AdvanceTime(base::Hours(1));
  UpdateChargeAndCurrent(6.0, -1.0);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(-2.0, status.observed_battery_charge_rate);

  // Switch to AC power and report a different charge. The rate should be
  // reported as 0 initially.
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kMainsType, kCharging);
  UpdateChargeAndCurrent(7.0, 1.0);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(0.0, status.observed_battery_charge_rate);

  // Let enough time pass for the battery readings to stabilize.
  SetStabilizedTime();
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(0.0, status.observed_battery_charge_rate);

  // Advance the time just enough for the rate to be calculated and increase the
  // charge by 1 Ah.
  test_api_->AdvanceTime(kObservationTime);
  UpdateChargeAndCurrent(8.0, 1.0);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(1.0 / (kObservationTime.InSecondsF() / 3600),
                   status.observed_battery_charge_rate);

  // Now advance the time to get a reading one hour from the first one and
  // decrease the charge by 2 Ah from the first reading while on AC power.
  test_api_->AdvanceTime(base::Hours(1) - kObservationTime);
  UpdateChargeAndCurrent(5.0, 1.0);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(-2.0, status.observed_battery_charge_rate);

  // Send enough identical samples to fill the window and check that the rate is
  // reported as 0.
  for (int i = 0; i < kMaxSamples; ++i) {
    test_api_->AdvanceTime(base::Hours(1));
    ASSERT_TRUE(UpdateStatus(&status));
  }
  EXPECT_DOUBLE_EQ(0.0, status.observed_battery_charge_rate);
}

TEST_F(PowerSupplyTest, LowBatteryShutdownSafetyPercent) {
  // Start out discharging on AC with a ludicrously-high current where all of
  // the charge will be drained in a minute.
  const double kCurrent = -60.0;
  WriteDefaultValues(PowerSource::AC);
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kMainsType, kDischarging);
  UpdateChargeAndCurrent(0.5, kCurrent);
  prefs_.SetInt64(kLowBatteryShutdownTimePref, 180);
  prefs_.SetDouble(kPowerSupplyFullFactorPref, 1.0);
  prefs_.SetInt64(kMaxCurrentSamplesPref, 1);
  Init();

  // The system shouldn't shut down initially since it's on AC power and a
  // negative charge rate hasn't yet been observed.
  SetStabilizedTime();
  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(30, status.battery_time_to_empty.InSeconds());
  EXPECT_EQ(0, status.battery_time_to_shutdown.InSeconds());
  EXPECT_DOUBLE_EQ(0.0, status.observed_battery_charge_rate);
  EXPECT_FALSE(status.battery_below_shutdown_threshold);

  // Even after a negative charge rate is observed, the system still shouldn't
  // shut down, since the battery percent is greater than the safety percent.
  test_api_->AdvanceTime(PowerSupply::kObservedBatteryChargeRateMin);
  UpdateChargeAndCurrent(0.25, kCurrent);
  ASSERT_GT(25.0, PowerSupply::kLowBatteryShutdownSafetyPercent);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(15, status.battery_time_to_empty.InSeconds());
  EXPECT_EQ(0, status.battery_time_to_shutdown.InSeconds());
  EXPECT_LT(status.observed_battery_charge_rate, 0.0);
  EXPECT_FALSE(status.battery_below_shutdown_threshold);
}

TEST_F(PowerSupplyTest, NotifyObserver) {
  // Set a long polling delay to ensure that PowerSupply doesn't poll in the
  // background during the test.
  const base::TimeDelta kDelay = base::Seconds(60);
  prefs_.SetInt64(kBatteryPollIntervalPref, kDelay.InMilliseconds());
  prefs_.SetInt64(kBatteryStabilizedAfterStartupMsPref,
                  kDelay.InMilliseconds());

  // Check that observers are notified about updates asynchronously.
  TestObserver observer(power_supply_.get());
  WriteDefaultValues(PowerSource::AC);
  Init();
  ASSERT_TRUE(power_supply_->RefreshImmediately());
  EXPECT_TRUE(observer.WaitForNotification());
}

TEST_F(PowerSupplyTest, RegisterForUdevEvents) {
  Init();
  EXPECT_TRUE(udev_.HasSubsystemObserver(PowerSupply::kUdevSubsystem,
                                         power_supply_.get()));

  PowerSupply* dead_ptr = power_supply_.get();
  power_supply_.reset();
  EXPECT_FALSE(
      udev_.HasSubsystemObserver(PowerSupply::kUdevSubsystem, dead_ptr));
}

TEST_F(PowerSupplyTest, IgnoreSpuriousUdevEvents) {
  TestObserver observer(power_supply_.get());
  WriteDefaultValues(PowerSource::AC);
  prefs_.SetInt64(kMaxCurrentSamplesPref, 1);
  prefs_.SetInt64(kLowBatteryShutdownTimePref, 0);
  prefs_.SetInt64(kBatteryStabilizedAfterStartupMsPref, 0);
  prefs_.SetInt64(kBatteryStabilizedAfterLinePowerConnectedMsPref, 0);
  prefs_.SetInt64(kBatteryStabilizedAfterLinePowerDisconnectedMsPref, 0);
  prefs_.SetDouble(kPowerSupplyFullFactorPref, 1.0);
  Init();

  const double kCharge = 0.5;
  const double kLowCurrent = 1.0;
  const double kHighCurrent = 2.0;

  // The amount of time that a battery at kCharge will take to reach full or
  // empty at kLowCurrent.
  const int kLowCurrentSec = 1800;

  // The notification from RefreshImmediately() should be asynchronous.
  UpdateChargeAndCurrent(kCharge, kLowCurrent);
  ASSERT_TRUE(power_supply_->RefreshImmediately());
  EXPECT_EQ(0, observer.num_updates());
  EXPECT_EQ(MakeEstimateString(false, 0, kLowCurrentSec),
            GetEstimateStringFromStatus(power_supply_->GetPowerStatus()));

  // Switch to battery power and check that a udev event triggers a synchronous
  // notification.
  UpdatePowerSourceAndBatteryStatus(PowerSource::BATTERY, kMainsType,
                                    kDischarging);
  SendUdevEvent(kUdevSubsystemAC);
  EXPECT_EQ(1, observer.num_updates());
  EXPECT_EQ(MakeEstimateString(false, kLowCurrentSec, 0),
            GetEstimateStringFromStatus(power_supply_->GetPowerStatus()));

  // A second udev event should be disregarded if nothing has changed. Even
  // though the current has changed, the battery estimates shouldn't be updated.
  UpdateChargeAndCurrent(kCharge, kHighCurrent);
  SendUdevEvent(kUdevSubsystemBAT0);
  EXPECT_EQ(1, observer.num_updates());
  EXPECT_EQ(MakeEstimateString(false, kLowCurrentSec, 0),
            GetEstimateStringFromStatus(power_supply_->GetPowerStatus()));

  // If the battery percentage changes, a new notification should be sent
  // to the observers.
  observer.reset_num_updates();
  UpdateChargeAndCurrent(kCharge - 0.1, kHighCurrent);
  SendUdevEvent(kUdevSubsystemBAT0);
  EXPECT_EQ(1, observer.num_updates());
  // Return to the low current and check that the high current sample wasn't
  // incorporated into the average.
  UpdateChargeAndCurrent(kCharge, kLowCurrent);
  EXPECT_EQ(MakeEstimateString(false, kLowCurrentSec, 0),
            UpdateAndGetEstimateString());

  // Switch to AC and check that another event triggers another notification and
  // updated estimates.
  observer.reset_num_updates();
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kMainsType, kCharging);
  SendUdevEvent(kUdevSubsystemAC);
  EXPECT_EQ(1, observer.num_updates());
  EXPECT_EQ(MakeEstimateString(false, 0, kLowCurrentSec),
            GetEstimateStringFromStatus(power_supply_->GetPowerStatus()));

  // Send another spurious event.
  UpdateChargeAndCurrent(kCharge, kHighCurrent);
  SendUdevEvent(kUdevSubsystemAC);
  EXPECT_EQ(1, observer.num_updates());
  EXPECT_EQ(MakeEstimateString(false, 0, kLowCurrentSec),
            GetEstimateStringFromStatus(power_supply_->GetPowerStatus()));

  // Check that the high current sample wasn't recorded.
  UpdateChargeAndCurrent(kCharge, kLowCurrent);
  EXPECT_EQ(MakeEstimateString(false, 0, kLowCurrentSec),
            UpdateAndGetEstimateString());

  // Add a power supply with an unknown type and check that it doesn't trigger a
  // notification.
  observer.reset_num_updates();
  const base::FilePath dir = temp_dir_.GetPath().Append("foo");
  ASSERT_TRUE(base::CreateDirectory(dir));
  WriteValue(dir, "type", kUnknownType);
  WriteValue(dir, "online", "1");
  WriteValue(dir, "status", kNotCharging);
  UpdateChargeAndCurrent(kCharge, kHighCurrent);
  SendUdevEvent("foo");
  EXPECT_EQ(0, observer.num_updates());
  EXPECT_EQ(MakeEstimateString(false, 0, kLowCurrentSec),
            GetEstimateStringFromStatus(power_supply_->GetPowerStatus()));

  // Switch the power supply's type so it's recognized and check that a
  // notification is sent.
  WriteValue(dir, "type", kUsbType);
  UpdateChargeAndCurrent(kCharge, kLowCurrent);
  SendUdevEvent(kUdevSubsystemUSBPD0);
  EXPECT_EQ(1, observer.num_updates());
  EXPECT_EQ(MakeEstimateString(false, 0, kLowCurrentSec),
            GetEstimateStringFromStatus(power_supply_->GetPowerStatus()));

  // An updated max current and voltage shouldn't generate a notification.
  WriteDoubleValue(dir, "current_max", 3.0);
  WriteDoubleValue(dir, "voltage_max_design", 20.0);
  SendUdevEvent(kUdevSubsystemUSBPD0);
  EXPECT_EQ(1, observer.num_updates());
  EXPECT_EQ(MakeEstimateString(false, 0, kLowCurrentSec),
            GetEstimateStringFromStatus(power_supply_->GetPowerStatus()));
}

TEST_F(PowerSupplyTest, SendPowerStatusOverDBus) {
  WriteDefaultValues(PowerSource::AC);
  Init();

  // On refresh, a PowerSupplyPoll signal should be emitted.
  ASSERT_TRUE(power_supply_->RefreshImmediately());
  PowerSupplyProperties proto;
  ASSERT_TRUE(
      dbus_wrapper_.GetSentSignal(0, kPowerSupplyPollSignal, &proto, nullptr));
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC, proto.external_power());
  EXPECT_DOUBLE_EQ(23.45, proto.preferred_minimum_external_power());

  WriteValue(ac_dir_, "online", "0");
  dbus_wrapper_.ClearSentSignals();
  ASSERT_TRUE(power_supply_->RefreshImmediately());
  proto.Clear();
  ASSERT_TRUE(
      dbus_wrapper_.GetSentSignal(0, kPowerSupplyPollSignal, &proto, nullptr));
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_DISCONNECTED,
            proto.external_power());
  EXPECT_DOUBLE_EQ(23.45, proto.preferred_minimum_external_power());

  // The latest properties should be sent when GetPowerSupplyProperties queried.
  dbus::MethodCall method_call(kPowerManagerInterface,
                               kGetPowerSupplyPropertiesMethod);
  std::unique_ptr<dbus::Response> response =
      dbus_wrapper_.CallExportedMethodSync(&method_call);
  ASSERT_TRUE(response);
  proto.Clear();
  ASSERT_TRUE(
      dbus::MessageReader(response.get()).PopArrayOfBytesAsProto(&proto));
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_DISCONNECTED,
            proto.external_power());
  EXPECT_DOUBLE_EQ(23.45, proto.preferred_minimum_external_power());
}

TEST_F(PowerSupplyTest, SendBatteryStatePollOverDBus) {
  WriteDefaultValues(PowerSource::AC);
  UpdateChargeAndCurrent(0.5, 0.0);
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kMainsType, kDischarging);
  Init();

  // On refresh, a PowerSupplyPoll signal should be emitted.
  ASSERT_TRUE(power_supply_->RefreshImmediately());
  std::unique_ptr<dbus::Signal> signal;
  ASSERT_TRUE(dbus_wrapper_.GetSentSignal(1, kBatteryStatePollSignal, nullptr,
                                          &signal));
  dbus::MessageReader reader(signal.get());
  uint32_t external_power_type;
  uint32_t battery_state;
  double battery_percentage;
  ASSERT_TRUE(reader.PopUint32(&external_power_type));
  ASSERT_TRUE(reader.PopUint32(&battery_state));
  ASSERT_TRUE(reader.PopDouble(&battery_percentage));
  ASSERT_FALSE(reader.HasMoreData());

  // AC charging maps to 1 in power_manager::system::ExternalPowerType.
  EXPECT_EQ(1, external_power_type);
  // Battery discharging maps to 2 in power_manager::system::UpowerBatteryState.
  EXPECT_EQ(2, battery_state);
  EXPECT_DOUBLE_EQ(50, battery_percentage);
}

TEST_F(PowerSupplyTest, SendGetBatteryStateOverDBus) {
  WriteDefaultValues(PowerSource::AC);
  UpdateChargeAndCurrent(0.5, 0.0);
  UpdatePowerSourceAndBatteryStatus(PowerSource::AC, kMainsType, kDischarging);
  Init();

  ASSERT_TRUE(power_supply_->RefreshImmediately());
  dbus_wrapper_.ClearSentSignals();

  // The latest properties should be sent when GetBatteryState queried.
  dbus::MethodCall method_call(kPowerManagerInterface, kGetBatteryStateMethod);
  std::unique_ptr<dbus::Response> response =
      dbus_wrapper_.CallExportedMethodSync(&method_call);
  dbus::MessageReader reader(response.get());
  uint32_t external_power_type;
  uint32_t battery_state;
  double battery_percentage;
  ASSERT_TRUE(reader.PopUint32(&external_power_type));
  ASSERT_TRUE(reader.PopUint32(&battery_state));
  ASSERT_TRUE(reader.PopDouble(&battery_percentage));
  ASSERT_FALSE(reader.HasMoreData());

  // AC charging maps to 1 in power_manager::system::ExternalPowerType.
  EXPECT_EQ(1, external_power_type);
  // Battery discharging maps to 2 in power_manager::system::UpowerBatteryState.
  EXPECT_EQ(2, battery_state);
  EXPECT_DOUBLE_EQ(50, battery_percentage);
}

TEST_F(PowerSupplyTest, CopyPowerStatusToProtocolBuffer) {
  // Start out with a status indicating that the system is charging.
  PowerStatus status;
  status.line_power_on = true;
  status.battery_energy_rate = 3.4;
  status.is_calculating_battery_time = false;
  status.battery_time_to_full = base::Seconds(900);
  status.display_battery_percentage = 75.8;
  status.battery_is_present = true;
  status.external_power = PowerSupplyProperties_ExternalPower_AC;
  status.battery_state = PowerSupplyProperties_BatteryState_CHARGING;
  status.supports_dual_role_devices = false;
  status.battery_vendor = "TEST_MFR";
  status.battery_voltage = kVoltage;
  status.battery_cycle_count = kCycleCount;
  status.battery_serial_number = kSerialNumber;
  status.battery_charge_full_design = kDefaultChargeFullDesign;
  status.battery_charge_full = kDefaultChargeFull;
  status.battery_voltage_min_design = kVoltageMinDesign;
  status.preferred_minimum_external_power = 12.34;

  PowerSupplyProperties proto;
  CopyPowerStatusToProtocolBuffer(status, &proto);
  EXPECT_EQ(status.external_power, proto.external_power());
  EXPECT_EQ(status.battery_state, proto.battery_state());
  EXPECT_DOUBLE_EQ(status.display_battery_percentage, proto.battery_percent());
  EXPECT_EQ(0, proto.battery_time_to_empty_sec());
  EXPECT_EQ(status.battery_time_to_full.InSeconds(),
            proto.battery_time_to_full_sec());
  EXPECT_FALSE(proto.is_calculating_battery_time());
  EXPECT_DOUBLE_EQ(-status.battery_energy_rate, proto.battery_discharge_rate());
  EXPECT_FALSE(proto.supports_dual_role_devices());
  EXPECT_EQ(status.battery_vendor, proto.battery_vendor());
  EXPECT_EQ(status.battery_voltage, proto.battery_voltage());
  EXPECT_EQ(status.battery_cycle_count, proto.battery_cycle_count());
  EXPECT_EQ(status.battery_serial_number, proto.battery_serial_number());
  EXPECT_DOUBLE_EQ(status.battery_charge_full_design,
                   proto.battery_charge_full_design());
  EXPECT_DOUBLE_EQ(status.battery_charge_full, proto.battery_charge_full());
  EXPECT_DOUBLE_EQ(status.battery_voltage_min_design,
                   proto.battery_voltage_min_design());
  EXPECT_DOUBLE_EQ(status.preferred_minimum_external_power,
                   proto.preferred_minimum_external_power());

  // Check that power source details are copied, but that ports that don't have
  // anything connected are ignored.
  const char kChargerId[] = "PORT1";
  const PowerSupplyProperties::PowerSource::Port kChargerPort =
      PowerSupplyProperties_PowerSource_Port_LEFT;
  const char kChargerManufacturerId[] = "ab4e";
  const char kChargerModelId[] = "0f31";
  const double kChargerMaxPower = 60.0;
  status.ports.push_back({kChargerId, kChargerPort, Role::DEDICATED_SOURCE,
                          kMainsType, kChargerManufacturerId, kChargerModelId,
                          kChargerMaxPower, true /* active_by_default */});
  const char kPhoneId[] = "PORT2";
  const PowerSupplyProperties::PowerSource::Port kPhonePort =
      PowerSupplyProperties_PowerSource_Port_RIGHT;
  const char kPhoneManufacturerId[] = "468b";
  const char kPhoneModelId[] = "0429";
  const double kPhoneMaxPower = 7.5;
  status.ports.push_back({kPhoneId, kPhonePort, Role::DUAL_ROLE, kUsbPdDrpType,
                          kPhoneManufacturerId, kPhoneModelId, kPhoneMaxPower,
                          false /* active_by_default */});
  status.ports.push_back({"PORT3", PowerSupplyProperties_PowerSource_Port_FRONT,
                          Role::NONE, kUnknownType, "", "", 0.0,
                          false /* active_by_default */});
  status.external_power_source_id = kChargerId;
  status.supports_dual_role_devices = true;

  proto.Clear();
  CopyPowerStatusToProtocolBuffer(status, &proto);
  EXPECT_EQ(kChargerId, proto.external_power_source_id());
  ASSERT_EQ(2u, proto.available_external_power_source_size());
  EXPECT_EQ(kChargerId, proto.available_external_power_source(0).id());
  EXPECT_EQ(kChargerPort, proto.available_external_power_source(0).port());
  EXPECT_EQ(PowerSupplyProperties_PowerSource_Type_MAINS,
            proto.available_external_power_source(0).type());
  EXPECT_EQ(kChargerManufacturerId,
            proto.available_external_power_source(0).manufacturer_id());
  EXPECT_EQ(kChargerModelId,
            proto.available_external_power_source(0).model_id());
  EXPECT_EQ(kChargerMaxPower,
            proto.available_external_power_source(0).max_power());
  EXPECT_TRUE(proto.available_external_power_source(0).active_by_default());
  EXPECT_EQ(kPhoneId, proto.available_external_power_source(1).id());
  EXPECT_EQ(kPhonePort, proto.available_external_power_source(1).port());
  EXPECT_EQ(PowerSupplyProperties_PowerSource_Type_USB_C,
            proto.available_external_power_source(1).type());
  EXPECT_EQ(kPhoneManufacturerId,
            proto.available_external_power_source(1).manufacturer_id());
  EXPECT_EQ(kPhoneModelId, proto.available_external_power_source(1).model_id());
  EXPECT_EQ(kPhoneMaxPower,
            proto.available_external_power_source(1).max_power());
  EXPECT_FALSE(proto.available_external_power_source(1).active_by_default());
  EXPECT_TRUE(proto.supports_dual_role_devices());

  // Now disconnect everything and start discharging.
  status.external_power_source_id.clear();
  status.ports.clear();
  status.line_power_on = false;
  status.battery_time_to_full = base::TimeDelta();
  status.battery_time_to_empty = base::Seconds(1800);
  status.battery_time_to_shutdown = base::Seconds(1500);
  status.external_power = PowerSupplyProperties_ExternalPower_DISCONNECTED;
  status.battery_state = PowerSupplyProperties_BatteryState_DISCHARGING;

  proto.Clear();
  CopyPowerStatusToProtocolBuffer(status, &proto);
  EXPECT_EQ(status.external_power, proto.external_power());
  EXPECT_EQ(status.battery_state, proto.battery_state());
  EXPECT_DOUBLE_EQ(status.display_battery_percentage, proto.battery_percent());
  EXPECT_EQ(status.battery_time_to_shutdown.InSeconds(),
            proto.battery_time_to_empty_sec());
  EXPECT_EQ(0, proto.battery_time_to_full_sec());
  EXPECT_FALSE(proto.is_calculating_battery_time());
  EXPECT_DOUBLE_EQ(status.battery_energy_rate, proto.battery_discharge_rate());
  EXPECT_EQ(0, proto.available_external_power_source_size());

  // Check that the is-calculating value is copied.
  status.is_calculating_battery_time = true;
  proto.Clear();
  CopyPowerStatusToProtocolBuffer(status, &proto);
  EXPECT_TRUE(proto.is_calculating_battery_time());
}

TEST_F(PowerSupplyTest, OmitBatteryFieldsWhenBatteryNotPresent) {
  // When a battery isn't present, battery-related fields should be omitted from
  // the protobuf.
  PowerStatus status;
  status.line_power_on = true;
  status.battery_is_present = false;
  status.external_power = PowerSupplyProperties_ExternalPower_AC;
  status.battery_state = PowerSupplyProperties_BatteryState_NOT_PRESENT;

  PowerSupplyProperties proto;
  CopyPowerStatusToProtocolBuffer(status, &proto);
  EXPECT_EQ(status.external_power, proto.external_power());
  EXPECT_EQ(status.battery_state, proto.battery_state());
  EXPECT_FALSE(proto.has_battery_percent());
  EXPECT_FALSE(proto.has_battery_time_to_empty_sec());
  EXPECT_FALSE(proto.has_battery_time_to_full_sec());
  EXPECT_FALSE(proto.has_is_calculating_battery_time());
  EXPECT_FALSE(proto.has_battery_discharge_rate());

  // powerd historically passed a battery_percent of -1 when a battery wasn't
  // present, so ensure the proto default matches this for backwards
  // compatibility: https://crbug.com/724903
  EXPECT_DOUBLE_EQ(-1.0, proto.battery_percent());
}

TEST_F(PowerSupplyTest, BatteryEnergyValue) {
  const double kCharge = 1.0;
  // Set energy_now attribute to charge times voltage + 1 to double check that
  // it is used instead of a value calculated from voltage and charge.
  const double kEnergy = kVoltage * kCharge + 1.0;

  WriteDefaultValues(PowerSource::BATTERY);
  UpdateChargeAndCurrent(kCharge, 0.0);
  WriteDoubleValue(battery_dir_, "energy_now", kEnergy);
  Init();

  // Check that the energy_now attribute is used for battery_energy when
  // available.
  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(kEnergy, status.battery_energy);
  EXPECT_DOUBLE_EQ(kCharge, status.battery_charge);
}

TEST_F(PowerSupplyTest, NoNominalVoltage) {
  const double kCharge = 0.5;
  const double kCurrent = 1.0;
  WriteDefaultValues(PowerSource::BATTERY);
  UpdateChargeAndCurrent(kCharge, kCurrent);

  // Remove the default min voltage attribute from the battery
  base::DeleteFile(battery_dir_.Append("voltage_min_design"));
  Init();

  // The battery should use the current voltage if there is no
  // voltage_min/max_design attribute.
  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(kVoltage, status.nominal_voltage);
  EXPECT_DOUBLE_EQ(kVoltage * kCharge, status.battery_energy);
  EXPECT_DOUBLE_EQ(kVoltage * kCurrent, status.battery_energy_rate);

  // If the current voltage is also zero, report failure rather than returning
  // bad data: http://crbug.com/671374
  WriteDoubleValue(battery_dir_, "voltage_now", 0.0);
  EXPECT_FALSE(UpdateStatus(&status));
}

TEST_F(PowerSupplyTest, NoCurrentOrVoltage) {
  WriteDefaultValues(PowerSource::AC);
  WriteDoubleValue(ac_dir_, "current_now", 2.0);
  WriteDoubleValue(ac_dir_, "voltage_now", 5.0);
  WriteDoubleValue(ac_dir_, "current_max", 3.0);
  WriteDoubleValue(ac_dir_, "voltage_max_design", 20.0);
  Init();
  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_TRUE(status.has_line_power_current);
  EXPECT_TRUE(status.has_line_power_voltage);
  EXPECT_TRUE(status.has_line_power_max_current);
  EXPECT_TRUE(status.has_line_power_max_voltage);

  // PowerSupply should report the lack of a current_now file:
  // https://crbug.com/807753
  base::DeleteFile(ac_dir_.Append("current_now"));
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_FALSE(status.has_line_power_current);

  // Ditto for voltage_now.
  base::DeleteFile(ac_dir_.Append("voltage_now"));
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_FALSE(status.has_line_power_voltage);

  // Ditto for current_max.
  base::DeleteFile(ac_dir_.Append("current_max"));
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_FALSE(status.has_line_power_max_current);

  // Ditto for voltage_max_design.
  base::DeleteFile(ac_dir_.Append("voltage_max_design"));
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_FALSE(status.has_line_power_max_voltage);
}

TEST_F(PowerSupplyTest, IgnoreMultipleBatteriesWithoutPref) {
  WriteDefaultValues(PowerSource::AC);
  AddSecondBattery(kCharging);
  Init();

  // Without kMultipleBatteriesPref, only the first battery should be read.
  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(kVoltage, status.battery_voltage);
  EXPECT_DOUBLE_EQ(kVoltage, status.nominal_voltage);
  EXPECT_DOUBLE_EQ(kDefaultCurrent, status.battery_current);
  EXPECT_DOUBLE_EQ(kDefaultCharge, status.battery_charge);
  EXPECT_DOUBLE_EQ(kDefaultChargeFull, status.battery_charge_full);
  EXPECT_DOUBLE_EQ(kDefaultChargeFullDesign, status.battery_charge_full_design);
}

TEST_F(PowerSupplyTest, MultipleBatteriesSummedValues) {
  WriteDefaultValues(PowerSource::AC);
  AddSecondBattery(kCharging);
  prefs_.SetInt64(kMultipleBatteriesPref, 1);
  constexpr double kShutdownPercent = 5.0;
  prefs_.SetDouble(kLowBatteryShutdownPercentPref, kShutdownPercent);
  Init();
  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));

  // Most battery-related fields should just contain the sum of the values read
  // or computed from sysfs.
  constexpr double kTotalCurrent = kDefaultCurrent + kDefaultSecondCurrent;
  constexpr double kTotalCharge = kDefaultCharge + kDefaultSecondCharge;
  constexpr double kTotalFullCharge =
      kDefaultChargeFull + kDefaultSecondChargeFull;
  constexpr double kTotalChargeFraction = kTotalCharge / kTotalFullCharge;

  EXPECT_DOUBLE_EQ(2 * kVoltage, status.battery_voltage);
  EXPECT_DOUBLE_EQ(2 * kVoltage, status.nominal_voltage);
  EXPECT_DOUBLE_EQ(kTotalCurrent, status.battery_current);
  EXPECT_DOUBLE_EQ(kTotalCharge, status.battery_charge);
  EXPECT_DOUBLE_EQ(kTotalFullCharge, status.battery_charge_full);
  EXPECT_DOUBLE_EQ(kDefaultChargeFullDesign + kDefaultSecondChargeFullDesign,
                   status.battery_charge_full_design);
  EXPECT_DOUBLE_EQ(kTotalCharge * kVoltage, status.battery_energy);
  EXPECT_DOUBLE_EQ(kTotalCurrent * kVoltage, status.battery_energy_rate);
  EXPECT_DOUBLE_EQ(100.0 * kTotalChargeFraction, status.battery_percentage);
  EXPECT_DOUBLE_EQ(100.0 * (100.0 * kTotalChargeFraction - kShutdownPercent) /
                       (100.0 * kFullFactor - kShutdownPercent),
                   status.display_battery_percentage);
}

TEST_F(PowerSupplyTest, MultipleBatteriesState) {
  WriteDefaultValues(PowerSource::AC);
  AddSecondBattery(kCharging);
  prefs_.SetInt64(kMultipleBatteriesPref, 1);
  Init();

  // When line power is online and batteries aren't full, and a positive current
  // is reported, a charging state should be reported.
  PowerStatus status;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC, status.external_power);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_CHARGING, status.battery_state);

  // The charging state should still be reported if one battery says it's
  // discharging.
  WriteValue(second_battery_dir_, "status", kDischarging);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC, status.external_power);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_CHARGING, status.battery_state);

  // When both batteries report a full charge while line power is online, a full
  // state should be reported.
  WriteValue(second_battery_dir_, "status", kCharging);
  WriteDoubleValue(battery_dir_, "charge_now", kDefaultChargeFull);
  WriteDoubleValue(second_battery_dir_, "charge_now", kDefaultSecondChargeFull);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC, status.external_power);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_FULL, status.battery_state);

  // If line power is online but the batteries aren't full and the combined
  // current is zero, a discharging state should be reported.
  WriteValue(battery_dir_, "status", kDischarging);
  WriteValue(second_battery_dir_, "status", kDischarging);
  WriteDoubleValue(battery_dir_, "current_now", 0.0);
  UpdateChargeAndCurrentForDir(second_battery_dir_, kDefaultSecondCharge, 0.0);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC, status.external_power);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_DISCHARGING,
            status.battery_state);

  // When line power is offline, a discharging state should be reported even if
  // one battery is charging (e.g. from the other).
  WriteValue(ac_dir_, "online", "0");
  WriteValue(battery_dir_, "status", kCharging);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_DISCONNECTED,
            status.external_power);
  EXPECT_EQ(PowerSupplyProperties_BatteryState_DISCHARGING,
            status.battery_state);
}

TEST_F(PowerSupplyTest, NotifyForUdevWithMultipleBatteries) {
  WriteDefaultValues(PowerSource::BATTERY);
  prefs_.SetInt64(kMultipleBatteriesPref, 1);
  Init();
  SendUdevEvent(kUdevSubsystemBAT0);

  // After adding a second battery, observers should be notified if a udev event
  // is received (but a second event should be ignored, since nothing's
  // changed).
  TestObserver observer(power_supply_.get());
  AddSecondBattery(kCharging);
  SendUdevEvent(kUdevSubsystemBAT1);
  EXPECT_EQ(1, observer.num_updates());
  SendUdevEvent(kUdevSubsystemBAT1);
  EXPECT_EQ(1, observer.num_updates());

  // The same thing should happen when the second battery is removed.
  ASSERT_TRUE(base::DeletePathRecursively(second_battery_dir_));
  SendUdevEvent(kUdevSubsystemBAT1);
  EXPECT_EQ(2, observer.num_updates());
  SendUdevEvent(kUdevSubsystemBAT1);
  EXPECT_EQ(2, observer.num_updates());
}

TEST_F(PowerSupplyTest, AdaptiveChargingTarget) {
  WriteDefaultValues(PowerSource::BATTERY);
  Init();

  double actual_charge = 0.75;
  UpdateChargeAndCurrent(actual_charge, kDefaultCurrent);
  power_supply_->SetAdaptiveChargingSupported(true);

  // The Adaptive Charging Target will override the existing values for
  // display_battery_percentage and battery_time_to_full.
  PowerStatus status;
  double hold_charge = 0.8;
  base::TimeDelta target_time_delta = base::Hours(4);
  power_supply_->SetAdaptiveCharging(target_time_delta, hold_charge);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ(hold_charge, status.display_battery_percentage);
  EXPECT_EQ(target_time_delta.InHours(), status.battery_time_to_full.InHours());
  EXPECT_TRUE(status.adaptive_delaying_charge);
  EXPECT_TRUE(status.adaptive_charging_supported);

  power_supply_->ClearAdaptiveChargingChargeDelay();
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_DOUBLE_EQ((100.0 * actual_charge) / kFullFactor,
                   status.display_battery_percentage);
  EXPECT_FALSE(status.adaptive_delaying_charge);
}

// Check that we set the battery_time_to_full to 0 when the
// `adaptive_charging_target_time_to_full_` is zero (Chrome interprets this as a
// max delay).
TEST_F(PowerSupplyTest, AdaptiveChargingZeroTargetTime) {
  WriteDefaultValues(PowerSource::BATTERY);
  Init();

  double actual_charge = 0.75;
  UpdateChargeAndCurrent(actual_charge, kDefaultCurrent);
  power_supply_->SetAdaptiveChargingSupported(true);

  PowerStatus status;
  double hold_charge = 0.8;
  power_supply_->SetAdaptiveCharging(base::TimeDelta(), hold_charge);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(base::TimeDelta(), status.battery_time_to_full);
}

// Test that the adaptive_charging_heuristic_enabled property is set in
// PowerStatus and the PowerSupplyProperties proto.
TEST_F(PowerSupplyTest, AdaptiveChargingHeuristic) {
  WriteDefaultValues(PowerSource::BATTERY);
  Init();

  double actual_charge = 0.75;
  PowerStatus status;
  PowerSupplyProperties proto;
  UpdateChargeAndCurrent(actual_charge, kDefaultCurrent);
  power_supply_->SetAdaptiveChargingSupported(true);
  power_supply_->SetAdaptiveChargingHeuristicEnabled(false);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_FALSE(status.adaptive_charging_heuristic_enabled);
  ASSERT_TRUE(
      dbus_wrapper_.GetSentSignal(0, kPowerSupplyPollSignal, &proto, nullptr));
  EXPECT_TRUE(proto.adaptive_charging_supported());
  EXPECT_FALSE(proto.adaptive_charging_heuristic_enabled());
  EXPECT_FALSE(proto.adaptive_delaying_charge());

  dbus_wrapper_.ClearSentSignals();
  proto.Clear();

  power_supply_->SetAdaptiveChargingHeuristicEnabled(true);
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_TRUE(status.adaptive_charging_heuristic_enabled);
  ASSERT_TRUE(
      dbus_wrapper_.GetSentSignal(0, kPowerSupplyPollSignal, &proto, nullptr));
  EXPECT_TRUE(proto.adaptive_charging_supported());
  EXPECT_TRUE(proto.adaptive_charging_heuristic_enabled());
  EXPECT_FALSE(proto.adaptive_delaying_charge());
}

// Test that barreljack AC is ignored when configured with no barreljack
TEST_F(PowerSupplyTest, BarreljackNotPresent) {
  TestObserver observer(power_supply_.get());
  WriteDefaultValues(PowerSource::AC);
  AddUSBPDCharger(true);
  prefs_.SetBool(kHasBarreljackPref, false);
  Init();

  PowerStatus status;
  PowerSupplyProperties proto;

  // No barreljack means udev event should be ignored
  SendUdevEvent(kUdevSubsystemAC);
  EXPECT_EQ(0, observer.num_updates());

  // AC directory should be ignored
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(1, status.ports.size());
  EXPECT_EQ("USB", status.ports[0].type);
  ASSERT_TRUE(
      dbus_wrapper_.GetSentSignal(0, kPowerSupplyPollSignal, &proto, nullptr));
  EXPECT_EQ(1, proto.available_external_power_source_size());
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_USB, proto.external_power());

  dbus_wrapper_.ClearSentSignals();
  proto.Clear();
}

// Test that barreljack AC is not ignored when configured with a barreljack
TEST_F(PowerSupplyTest, BarreljackPresent) {
  WriteDefaultValues(PowerSource::AC);
  prefs_.SetBool(kHasBarreljackPref, true);
  Init();

  PowerStatus status;
  PowerSupplyProperties proto;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(1, status.ports.size());
  EXPECT_EQ("Mains", status.ports[0].type);
  ASSERT_TRUE(
      dbus_wrapper_.GetSentSignal(0, kPowerSupplyPollSignal, &proto, nullptr));
  EXPECT_EQ(1, proto.available_external_power_source_size());
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_AC, proto.external_power());

  dbus_wrapper_.ClearSentSignals();
  proto.Clear();
}

// Test that barreljack AC is not ignored when configured with a barreljack
// and USB charging
TEST_F(PowerSupplyTest, BarreljackAndUSBPresent) {
  WriteDefaultValues(PowerSource::AC);
  AddUSBPDCharger(true);
  prefs_.SetBool(kHasBarreljackPref, true);
  Init();

  PowerStatus status;
  PowerSupplyProperties proto;
  ASSERT_TRUE(UpdateStatus(&status));
  EXPECT_EQ(2, status.ports.size());
  EXPECT_EQ("Mains", status.ports[0].type);
  EXPECT_EQ("USB", status.ports[1].type);
  ASSERT_TRUE(
      dbus_wrapper_.GetSentSignal(0, kPowerSupplyPollSignal, &proto, nullptr));
  EXPECT_EQ(2, proto.available_external_power_source_size());
  EXPECT_EQ(PowerSupplyProperties_ExternalPower_USB, proto.external_power());

  dbus_wrapper_.ClearSentSignals();
  proto.Clear();
}

}  // namespace power_manager::system
