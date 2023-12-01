// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <map>
#include <memory>
#include <utility>

#include <base/memory/scoped_refptr.h>
#include <brillo/errors/error.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "debugd/dbus-proxy-mocks.h"
#include "diagnostics/cros_healthd/fetchers/battery_fetcher.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "power_manager/proto_bindings/power_supply_properties.pb.h"

namespace diagnostics {
namespace {

using ::ash::cros_healthd::mojom::ErrorType;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::WithArg;

// Arbitrary test values for the various battery metrics.
constexpr power_manager::PowerSupplyProperties_BatteryState kBatteryStateFull =
    power_manager::PowerSupplyProperties_BatteryState_FULL;
constexpr char kBatteryVendor[] = "TEST_MFR";
constexpr double kBatteryVoltage = 127.45;
constexpr int kBatteryCycleCount = 2;
constexpr char kBatterySerialNumber[] = "1000";
constexpr double kBatteryVoltageMinDesign = 114.00;
constexpr double kBatteryChargeFull = 4.3;
constexpr double kBatteryChargeFullDesign = 3.92;
constexpr char kBatteryModelName[] = "TEST_MODEL_NAME";
constexpr double kBatteryChargeNow = 5.17;
constexpr char kSmartBatteryManufactureDateResponse[] =
    "Read from I2C port 2 at 0xb offset 0x1b = 0x4d06";
constexpr char kSmartBatteryManufactureDate[] = "2018-08-06";
constexpr char kSmartBatteryTemperatureResponse[] =
    "Read from I2C port 2 at 0xb offset 0x8 = 0xbae";
constexpr uint64_t kSmartBatteryTemperature = 2990;
constexpr char kInvalidRegexSmartMetricResponse[] =
    "this does not match the regex";
constexpr double kBatteryCurrentNow = 6.45;
constexpr char kBatteryTechnology[] = "Battery technology.";
constexpr char kBatteryStatus[] = "Discharging";

// Timeouts for the Debugd D-Bus calls. Note that D-Bus is mocked out in the
// test, but the timeouts are still part of the mock calls.
constexpr int kDebugdTimeOut = 10 * 1000;

class BatteryFetcherTest : public ::testing::Test {
 protected:
  BatteryFetcherTest() = default;

  void SetUp() override {
    SetHasSmartBatteryInfo(true);
  }

  BatteryFetcher* battery_fetcher() { return &battery_fetcher_; }

  org::chromium::debugdProxyMock* mock_debugd_proxy() {
    return mock_context_.mock_debugd_proxy();
  }

  FakePowerdAdapter* fake_powerd_adapter() {
    return mock_context_.fake_powerd_adapter();
  }

  void SetHasBattery(const bool value) {
    mock_context_.fake_system_config()->SetHasBattery(value);
  }

  void SetHasSmartBatteryInfo(const bool value) {
    mock_context_.fake_system_config()->SetHasSmartBattery(value);
  }

 private:
  MockContext mock_context_;
  BatteryFetcher battery_fetcher_{&mock_context_};
};

// Test that we can fetch all battery metrics correctly.
TEST_F(BatteryFetcherTest, FetchBatteryInfo) {
  // Create PowerSupplyProperties response protobuf.
  power_manager::PowerSupplyProperties power_supply_proto;
  power_supply_proto.set_battery_state(kBatteryStateFull);
  power_supply_proto.set_battery_vendor(kBatteryVendor);
  power_supply_proto.set_battery_voltage(kBatteryVoltage);
  power_supply_proto.set_battery_cycle_count(kBatteryCycleCount);
  power_supply_proto.set_battery_charge_full(kBatteryChargeFull);
  power_supply_proto.set_battery_charge_full_design(kBatteryChargeFullDesign);
  power_supply_proto.set_battery_serial_number(kBatterySerialNumber);
  power_supply_proto.set_battery_voltage_min_design(kBatteryVoltageMinDesign);
  power_supply_proto.set_battery_model_name(kBatteryModelName);
  power_supply_proto.set_battery_charge(kBatteryChargeNow);
  power_supply_proto.set_battery_current(kBatteryCurrentNow);
  power_supply_proto.set_battery_technology(kBatteryTechnology);
  power_supply_proto.set_battery_status(kBatteryStatus);

  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  // Set the mock Debugd Adapter responses.
  EXPECT_CALL(
      *mock_debugd_proxy(),
      CollectSmartBatteryMetric("manufacture_date_smart", _, _, kDebugdTimeOut))
      .WillOnce(DoAll(WithArg<1>(Invoke([](std::string* result) {
                        *result = kSmartBatteryManufactureDateResponse;
                      })),
                      Return(true)));
  EXPECT_CALL(
      *mock_debugd_proxy(),
      CollectSmartBatteryMetric("temperature_smart", _, _, kDebugdTimeOut))
      .WillOnce(DoAll(WithArg<1>(Invoke([](std::string* result) {
                        *result = kSmartBatteryTemperatureResponse;
                      })),
                      Return(true)));

  auto battery_result = battery_fetcher()->FetchBatteryInfo();
  ASSERT_TRUE(battery_result->is_battery_info());

  const auto& battery = battery_result->get_battery_info();
  EXPECT_EQ(kBatteryCycleCount, battery->cycle_count);
  EXPECT_EQ(kBatteryVendor, battery->vendor);
  EXPECT_EQ(kBatteryVoltage, battery->voltage_now);
  EXPECT_EQ(kBatteryChargeFull, battery->charge_full);
  EXPECT_EQ(kBatteryChargeFullDesign, battery->charge_full_design);
  EXPECT_EQ(kBatterySerialNumber, battery->serial_number);
  EXPECT_EQ(kBatteryVoltageMinDesign, battery->voltage_min_design);
  EXPECT_EQ(kBatteryModelName, battery->model_name);
  EXPECT_EQ(kBatteryChargeNow, battery->charge_now);
  EXPECT_EQ(kBatteryCurrentNow, battery->current_now);
  EXPECT_EQ(kBatteryTechnology, battery->technology);
  EXPECT_EQ(kBatteryStatus, battery->status);

  // Test that optional smart battery metrics are populated.
  ASSERT_TRUE(battery->manufacture_date.has_value());
  ASSERT_TRUE(battery->temperature);
  EXPECT_EQ(kSmartBatteryManufactureDate, battery->manufacture_date.value());
  EXPECT_EQ(kSmartBatteryTemperature, battery->temperature->value);
}

// Test that an empty proto in a power_manager D-Bus response returns an error.
TEST_F(BatteryFetcherTest, EmptyProtoPowerManagerDbusResponse) {
  power_manager::PowerSupplyProperties power_supply_proto;
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);
  auto battery_result = battery_fetcher()->FetchBatteryInfo();
  ASSERT_TRUE(battery_result->is_error());
  EXPECT_EQ(battery_result->get_error()->type, ErrorType::kSystemUtilityError);
}

// Test that debugd failing to collect battery manufacture date returns an
// error.
TEST_F(BatteryFetcherTest, ManufactureDateRetrievalFailure) {
  power_manager::PowerSupplyProperties power_supply_proto;
  power_supply_proto.set_battery_state(kBatteryStateFull);
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  // Set the mock Debugd Adapter responses.
  EXPECT_CALL(
      *mock_debugd_proxy(),
      CollectSmartBatteryMetric("manufacture_date_smart", _, _, kDebugdTimeOut))
      .WillOnce(DoAll(WithArg<2>(Invoke([](brillo::ErrorPtr* error) {
                        *error = brillo::Error::Create(FROM_HERE, "", "", "");
                      })),
                      Return(false)));

  auto battery_result = battery_fetcher()->FetchBatteryInfo();
  ASSERT_TRUE(battery_result->is_error());
  EXPECT_EQ(battery_result->get_error()->type, ErrorType::kSystemUtilityError);
}

// Test that debugd failing to collect battery temperature returns an error.
TEST_F(BatteryFetcherTest, TemperatureRetrievalFailure) {
  power_manager::PowerSupplyProperties power_supply_proto;
  power_supply_proto.set_battery_state(kBatteryStateFull);
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  // Set the mock Debugd Adapter responses.
  EXPECT_CALL(
      *mock_debugd_proxy(),
      CollectSmartBatteryMetric("manufacture_date_smart", _, _, kDebugdTimeOut))
      .WillOnce(DoAll(WithArg<1>(Invoke([](std::string* result) {
                        *result = kSmartBatteryManufactureDateResponse;
                      })),
                      Return(true)));
  EXPECT_CALL(
      *mock_debugd_proxy(),
      CollectSmartBatteryMetric("temperature_smart", _, _, kDebugdTimeOut))
      .WillOnce(DoAll(WithArg<2>(Invoke([](brillo::ErrorPtr* error) {
                        *error = brillo::Error::Create(FROM_HERE, "", "", "");
                      })),
                      Return(false)));

  auto battery_result = battery_fetcher()->FetchBatteryInfo();
  ASSERT_TRUE(battery_result->is_error());
  EXPECT_EQ(battery_result->get_error()->type, ErrorType::kSystemUtilityError);
}

// Test that failing to match the regex to the debugd responses returns an
// error.
TEST_F(BatteryFetcherTest, SmartMetricRegexFailure) {
  power_manager::PowerSupplyProperties power_supply_proto;
  power_supply_proto.set_battery_state(kBatteryStateFull);
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  // Set the mock Debugd Adapter responses.
  EXPECT_CALL(
      *mock_debugd_proxy(),
      CollectSmartBatteryMetric("manufacture_date_smart", _, _, kDebugdTimeOut))
      .WillOnce(DoAll(WithArg<1>(Invoke([](std::string* result) {
                        *result = kInvalidRegexSmartMetricResponse;
                      })),
                      Return(true)));

  auto battery_result = battery_fetcher()->FetchBatteryInfo();
  ASSERT_TRUE(battery_result->is_error());
  EXPECT_EQ(battery_result->get_error()->type, ErrorType::kParseError);
}

// Test that Smart Battery metrics are not fetched when a device does not have a
// Smart Battery.
TEST_F(BatteryFetcherTest, NoSmartBattery) {
  SetHasSmartBatteryInfo(false);

  // Set the mock power manager response.
  power_manager::PowerSupplyProperties power_supply_proto;
  power_supply_proto.set_battery_state(kBatteryStateFull);
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  auto battery_result = battery_fetcher()->FetchBatteryInfo();
  ASSERT_TRUE(battery_result->is_battery_info());
  const auto& battery = battery_result->get_battery_info();

  EXPECT_FALSE(battery->manufacture_date.has_value());
  EXPECT_FALSE(battery->temperature);
}

// Test that no battery info is returned when a device does not have a battery.
TEST_F(BatteryFetcherTest, NoBattery) {
  SetHasBattery(false);
  auto battery_result = battery_fetcher()->FetchBatteryInfo();
  ASSERT_TRUE(battery_result->get_battery_info().is_null());
}

}  // namespace
}  // namespace diagnostics
