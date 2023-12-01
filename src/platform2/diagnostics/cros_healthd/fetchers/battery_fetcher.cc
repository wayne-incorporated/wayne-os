// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/battery_fetcher.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/process/launch.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/values.h>
#include <re2/re2.h>

#include "debugd/dbus-proxies.h"
#include "diagnostics/cros_healthd/utils/error_utils.h"
#include "power_manager/proto_bindings/power_supply_properties.pb.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

// The name of the Smart Battery manufacture date metric.
constexpr char kManufactureDateSmart[] = "manufacture_date_smart";
// The name of the Smart Battery temperature metric.
constexpr char kTemperatureSmart[] = "temperature_smart";

// The maximum amount of time to wait for a debugd response.
constexpr int kDebugdDBusTimeout = 10 * 1000;

// Converts a Smart Battery manufacture date from the ((year - 1980) * 512 +
// month * 32 + day) format to yyyy-mm-dd format.
std::string ConvertSmartBatteryManufactureDate(uint32_t manufacture_date) {
  int remainder = manufacture_date;
  int day = remainder % 32;
  remainder /= 32;
  int month = remainder % 16;
  remainder /= 16;
  int year = remainder + 1980;
  return base::StringPrintf("%04d-%02d-%02d", year, month, day);
}

}  // namespace

mojom::BatteryResultPtr BatteryFetcher::FetchBatteryInfo() {
  if (!context_->system_config()->HasBattery())
    return mojom::BatteryResult::NewBatteryInfo(mojom::BatteryInfoPtr());

  mojom::BatteryInfo info;
  auto power_supply_proto =
      context_->powerd_adapter()->GetPowerSupplyProperties();
  if (!power_supply_proto) {
    return mojom::BatteryResult::NewError(CreateAndLogProbeError(
        mojom::ErrorType::kSystemUtilityError,
        "Failed to obtain power supply properties from powerd"));
  }

  auto error =
      PopulateBatteryInfoFromPowerdResponse(power_supply_proto.value(), &info);
  if (error.has_value()) {
    return mojom::BatteryResult::NewError(std::move(error.value()));
  }

  if (context_->system_config()->HasSmartBattery()) {
    error = PopulateSmartBatteryInfo(&info);
    if (error.has_value()) {
      return mojom::BatteryResult::NewError(std::move(error.value()));
    }
  }

  return mojom::BatteryResult::NewBatteryInfo(info.Clone());
}

std::optional<mojom::ProbeErrorPtr>
BatteryFetcher::PopulateBatteryInfoFromPowerdResponse(
    const power_manager::PowerSupplyProperties& power_supply_proto,
    mojom::BatteryInfo* info) {
  DCHECK(info);

  if (!power_supply_proto.has_battery_state() ||
      power_supply_proto.battery_state() ==
          power_manager::PowerSupplyProperties_BatteryState_NOT_PRESENT) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kSystemUtilityError,
        "PowerSupplyProperties protobuf indicates battery is not present");
  }

  info->cycle_count = power_supply_proto.battery_cycle_count();
  info->vendor = power_supply_proto.battery_vendor();
  info->voltage_now = power_supply_proto.battery_voltage();
  info->charge_full = power_supply_proto.battery_charge_full();
  info->charge_full_design = power_supply_proto.battery_charge_full_design();
  info->serial_number = power_supply_proto.battery_serial_number();
  info->voltage_min_design = power_supply_proto.battery_voltage_min_design();
  info->model_name = power_supply_proto.battery_model_name();
  info->charge_now = power_supply_proto.battery_charge();
  info->current_now = power_supply_proto.battery_current();
  info->technology = power_supply_proto.battery_technology();
  info->status = power_supply_proto.battery_status();

  return std::nullopt;
}

std::optional<mojom::ProbeErrorPtr> BatteryFetcher::PopulateSmartBatteryInfo(
    mojom::BatteryInfo* info) {
  uint32_t manufacture_date;
  auto convert_hex_string_to_uint32 =
      base::BindOnce([](const base::StringPiece& input, uint32_t* output) {
        return base::HexStringToUInt(input, output);
      });
  auto error = GetSmartBatteryMetric(kManufactureDateSmart,
                                     std::move(convert_hex_string_to_uint32),
                                     &manufacture_date);
  if (error.has_value()) {
    return error;
  }
  info->manufacture_date = ConvertSmartBatteryManufactureDate(manufacture_date);

  uint64_t temperature;
  auto convert_hex_string_to_uint64 =
      base::BindOnce([](const base::StringPiece& input, uint64_t* output) {
        return base::HexStringToUInt64(input, output);
      });
  error = GetSmartBatteryMetric(
      kTemperatureSmart, std::move(convert_hex_string_to_uint64), &temperature);
  if (error.has_value()) {
    return error;
  }
  info->temperature = mojom::NullableUint64::New(temperature);

  return std::nullopt;
}

template <typename T>
std::optional<mojom::ProbeErrorPtr> BatteryFetcher::GetSmartBatteryMetric(
    const std::string& metric_name,
    base::OnceCallback<bool(const base::StringPiece& input, T* output)>
        convert_string_to_num,
    T* metric_value) {
  brillo::ErrorPtr error;
  std::string debugd_result;
  if (!context_->debugd_proxy()->CollectSmartBatteryMetric(
          metric_name, &debugd_result, &error, kDebugdDBusTimeout)) {
    return CreateAndLogProbeError(mojom::ErrorType::kSystemUtilityError,
                                  "Failed retrieving " + metric_name +
                                      " from debugd: " + error->GetCode() +
                                      " " + error->GetMessage());
  }

  // Parse the output from debugd to obtain the battery metric.
  constexpr auto kRegexPattern =
      R"(^Read from I2C port [\d]+ at .* offset .* = (.+)$)";
  std::string reg_value;
  if (!RE2::PartialMatch(base::CollapseWhitespaceASCII(debugd_result, true),
                         kRegexPattern, &reg_value)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to match debugd output to regex: " + debugd_result);
  }

  if (!std::move(convert_string_to_num).Run(reg_value, metric_value)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Unable to run convert string to num callback");
  }

  return std::nullopt;
}

}  // namespace diagnostics
