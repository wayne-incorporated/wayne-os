// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/functions/generic_battery.h"

#include <pcrecpp.h>

#include <string>
#include <utility>

#include <base/containers/fixed_flat_set.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/values.h>
#include <brillo/errors/error.h>
#include <debugd/dbus-proxies.h>

#include "runtime_probe/system/context.h"
#include "runtime_probe/utils/file_utils.h"

namespace runtime_probe {

namespace {

constexpr auto kSysfsPowerSupplyPath = "sys/class/power_supply/*";
constexpr auto kSysfsExpectedType = "Battery";

// Conversion factor from mAh to uAh.
constexpr uint32_t kmAhTouAhMultiplier = 1000;

// These keys are expected to present no matter what types of battery is:
constexpr auto kBatteryKeys = base::MakeFixedFlatSet<base::StringPiece>(
    {"manufacturer", "model_name", "technology", "type"});

// These keys are optional
constexpr auto kBatteryOptionalKeys = base::MakeFixedFlatSet<base::StringPiece>(
    {"capacity", "capacity_level", "charge_full", "charge_full_design",
     "present", "serial_number", "voltage_min_design"});

std::optional<base::Value::Dict> ProbeBatteryFromSysfs(
    const base::FilePath& battery_path) {
  auto value = MapFilesToDict(battery_path, kBatteryKeys, kBatteryOptionalKeys);
  if (!value)
    return std::nullopt;
  auto dict_value = std::move(value->GetDict());

  const std::string* power_supply_type = dict_value.FindString("type");
  DCHECK(power_supply_type != nullptr);

  if (*power_supply_type != kSysfsExpectedType) {
    VLOG(2) << "Unexpected power supply type from " << battery_path.value()
            << ", got " << *power_supply_type;
    return std::nullopt;
  }

  dict_value.Set("path", battery_path.value());
  return dict_value;
}

std::optional<base::Value::Dict> ProbeBatteryFromEc() {
  std::string output;
  brillo::ErrorPtr error;
  auto debugd = Context::Get()->debugd_proxy();
  if (!debugd->BatteryFirmware("info", &output, &error)) {
    std::string err_message = "(no error message)";
    if (error)
      err_message = error->GetMessage();
    LOG(ERROR) << "debugd::BatteryFirmware failed: " << err_message;
    return std::nullopt;
  }

  // TODO(itspeter): Extra take care if there are multiple batteries.
  base::Value::Dict bat;
  pcrecpp::RE re(R"(Battery (?:\d+ )?info:\n)"
                 R"(  OEM name *: *(.*)\n)"
                 R"(  Model number *: *(.*)\n)"
                 R"(  Chemistry *: *(.*)\n)"
                 R"(  Serial number *: *\w+\n)"
                 R"(  Design capacity *: *(\d+) mAh\n)",
                 pcrecpp::RE_Options(PCRE_MULTILINE));
  std::string mfr, model, chem, cap;
  if (!re.PartialMatch(output, &mfr, &model, &chem, &cap)) {
    return std::nullopt;
  }
  bat.Set("manufacturer", mfr);
  bat.Set("model_name", model);
  bat.Set("chemistry", chem);
  int64_t cap_num_mah;
  CHECK(base::StringToInt64(cap, &cap_num_mah));
  bat.Set("charge_full_design",
          base::NumberToString(cap_num_mah * kmAhTouAhMultiplier));
  return bat;
}

}  // namespace

GenericBattery::DataType GenericBattery::EvalImpl() const {
  DataType result{};

  const auto rooted_pattern =
      Context::Get()->root_dir().Append(kSysfsPowerSupplyPath);
  for (const auto& battery_path : Glob(rooted_pattern)) {
    auto node_res = ProbeBatteryFromSysfs(battery_path);
    if (!node_res)
      continue;
    result.Append(std::move(*node_res));
  }

  // TODO(itspeter): Extra take care if there are multiple batteries.
  if (result.size() > 1) {
    LOG(ERROR) << "Multiple batteries is not supported yet.";
    return {};
  }

  return result;
}

void GenericBattery::PostHelperEvalImpl(
    GenericBattery::DataType* result) const {
  auto bat_ec = ProbeBatteryFromEc();
  if (bat_ec) {
    const std::string* mfr_ec = bat_ec->FindString("manufacturer");
    const std::string* model_ec = bat_ec->FindString("model_name");
    CHECK(mfr_ec != nullptr);
    CHECK(model_ec != nullptr);
    bool find_match = false;
    for (auto& bat_sysfs : *result) {
      const std::string* mfr_sysfs =
          bat_sysfs.GetDict().FindString("manufacturer");
      const std::string* model_sysfs =
          bat_sysfs.GetDict().FindString("model_name");
      CHECK(mfr_sysfs != nullptr);
      CHECK(model_sysfs != nullptr);
      // Check if values in sysfs are prefixes of values in EC.
      if (base::StartsWith(*mfr_ec, *mfr_sysfs) &&
          base::StartsWith(*model_ec, *model_sysfs)) {
        bat_sysfs.GetDict().Merge(std::move(*bat_ec));
        find_match = true;
        break;
      }
    }
    LOG_IF(ERROR, !find_match) << "No matching battery found in sysfs.";
  }
}

}  // namespace runtime_probe
