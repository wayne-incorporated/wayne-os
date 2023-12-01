// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iomanip>
#include <iostream>  // NOLINT(readability/streams)
#include <memory>
#include <string>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/message_loop/message_pump_type.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_executor.h>
#include <base/time/time.h>
#include <brillo/flag_helper.h>
#include <libec/ec_command_factory.h>

#include "power_manager/common/battery_percentage_converter.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"
#include "power_manager/powerd/system/dbus_wrapper_stub.h"
#include "power_manager/powerd/system/power_supply.h"
#include "power_manager/powerd/system/udev_stub.h"

// Displays info about battery and line power.

using base::TimeDelta;
using power_manager::system::PowerStatus;

namespace {

// Number of columns that should be used to display field names.
const int kFieldNameColumns = 27;

// Number of retry attempts for reading the PowerStatus.
static const int kPowerRefreshRetries = 3;

std::string BoolToString(bool value) {
  return value ? "yes" : "no";
}

template <class T>
std::string ValueToString(T value) {
  std::stringstream stream;
  stream << value;
  return stream.str();
}

class InfoDisplay {
 public:
  InfoDisplay() = default;
  InfoDisplay(const InfoDisplay&) = delete;
  InfoDisplay& operator=(const InfoDisplay&) = delete;

  void SetIndent(int name_indent, int value_indent) {
    name_indent_ = name_indent;
    value_indent_ = value_indent;
  }

  void PrintStringValue(const std::string& name_field,
                        const std::string& value_field) {
    std::cout << std::setw(name_indent_) << ""
              << std::setw(value_indent_ - name_indent_)
              << std::setiosflags(std::ios::left)
              << std::resetiosflags(std::ios::right) << name_field + ":"
              << value_field << std::endl;
  }

  template <class T>
  void PrintValue(const std::string& name_field, T value) {
    PrintStringValue(name_field, ValueToString(value));
  }

  void PrintString(const std::string& string) {
    std::cout << std::setw(name_indent_) << "" << string << std::endl;
  }

 private:
  int name_indent_ = 0;
  int value_indent_ = 0;
};

}  // namespace

int main(int argc, char** argv) {
  brillo::FlagHelper::Init(
      argc, argv,
      "Print information obtained from /sys about the power supply.");
  base::AtExitManager at_exit_manager;
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  logging::SetMinLogLevel(logging::LOGGING_WARNING);

  power_manager::Prefs prefs;
  CHECK(prefs.Init(power_manager::Prefs::GetDefaultStore(),
                   power_manager::Prefs::GetDefaultSources()));

  power_manager::system::UdevStub udev;
  power_manager::system::DBusWrapperStub dbus_wrapper;
  base::FilePath path(power_manager::kPowerStatusPath);
  base::FilePath cros_ec_path(ec::kCrosEcPath);
  ec::EcCommandFactory ec_command_factory;

  auto battery_percentage_converter =
      power_manager::BatteryPercentageConverter::CreateFromPrefs(&prefs);

  power_manager::system::PowerSupply power_supply;
  power_supply.Init(path, cros_ec_path, &ec_command_factory, &prefs, &udev,
                    &dbus_wrapper, battery_percentage_converter.get());

  bool success = false;
  for (int i = 0; i < kPowerRefreshRetries; i++) {
    success = power_supply.RefreshImmediately();
    if (success)
      break;
    // Backoff before retrying
    base::PlatformThread::Sleep(base::Milliseconds(1 << i));
  }

  CHECK(success);
  const PowerStatus status = power_supply.GetPowerStatus();

  // NOTE, autotests (see autotest/files/client/cros/power_status.py) rely on
  // parsing this information below.
  // DO NOT CHANGE formatting without also fixing there as well.
  InfoDisplay display;
  display.SetIndent(0, 0);
  display.PrintString("Device: Line Power");
  display.SetIndent(2, kFieldNameColumns);
  display.PrintValue("path", status.line_power_path);
  display.PrintStringValue("online", BoolToString(status.line_power_on));
  display.PrintStringValue("type", status.line_power_type);
  switch (status.external_power) {
    case power_manager::PowerSupplyProperties_ExternalPower_AC:
      display.PrintStringValue("enum type", "AC");
      break;
    case power_manager::PowerSupplyProperties_ExternalPower_USB:
      display.PrintStringValue("enum type", "USB");
      break;
    case power_manager::PowerSupplyProperties_ExternalPower_DISCONNECTED:
      display.PrintStringValue("enum type", "Disconnected");
      break;
    default:
      display.PrintStringValue("enum type", "Unknown");
  }

  if (status.has_line_power_voltage)
    display.PrintValue("voltage (V)", status.line_power_voltage);
  else
    display.PrintValue("voltage (V)", "Not available");

  if (status.has_line_power_current)
    display.PrintValue("current (A)", status.line_power_current);
  else
    display.PrintValue("current (A)", "Not available");

  if (status.has_line_power_max_voltage)
    display.PrintValue("max voltage (V)", status.line_power_max_voltage);
  else
    display.PrintValue("max voltage (V)", "Not available");

  if (status.has_line_power_max_current)
    display.PrintValue("max current (A)", status.line_power_max_current);
  else
    display.PrintValue("max current (A)", "Not available");

  display.PrintStringValue("active source", status.external_power_source_id);
  std::vector<std::string> sources;
  for (const auto& port : status.ports) {
    if (port.role == PowerStatus::Port::Role::DEDICATED_SOURCE ||
        port.role == PowerStatus::Port::Role::DUAL_ROLE) {
      sources.push_back(base::StringPrintf(
          "%s%s [%s/%s]", port.id.c_str(), port.active_by_default ? "*" : "",
          port.manufacturer_id.c_str(), port.model_id.c_str()));
    }
  }
  display.PrintStringValue("available sources",
                           base::JoinString(sources, ", "));

  display.PrintStringValue("supports dual-role",
                           BoolToString(status.supports_dual_role_devices));

  if (status.battery_is_present) {
    display.SetIndent(0, 0);
    display.PrintString("Device: Battery");
    display.SetIndent(2, kFieldNameColumns);
    display.PrintValue("path", status.battery_path);
    display.PrintStringValue("vendor", status.battery_vendor);
    display.PrintStringValue("model name", status.battery_model_name);

    switch (status.battery_state) {
      case power_manager::PowerSupplyProperties_BatteryState_FULL:
        display.PrintStringValue("state", "Fully charged");
        break;
      case power_manager::PowerSupplyProperties_BatteryState_CHARGING:
        display.PrintStringValue("state", "Charging");
        break;
      case power_manager::PowerSupplyProperties_BatteryState_DISCHARGING:
        display.PrintStringValue("state", "Discharging");
        break;
      case power_manager::PowerSupplyProperties_BatteryState_NOT_PRESENT:
        display.PrintStringValue("state", "Not present");
        break;
      default:
        display.PrintStringValue("state", "Unknown");
    }

    display.PrintValue("voltage (V)", status.battery_voltage);
    display.PrintValue("energy (Wh)", status.battery_energy);
    display.PrintValue("energy rate (W)", status.battery_energy_rate);
    display.PrintValue("current (A)", status.battery_current);
    display.PrintValue("charge (Ah)", status.battery_charge);
    display.PrintValue("full charge (Ah)", status.battery_charge_full);
    display.PrintValue("full charge design (Ah)",
                       status.battery_charge_full_design);
    display.PrintValue("percentage", status.battery_percentage);
    display.PrintValue("display percentage", status.display_battery_percentage);
    display.PrintStringValue("technology", status.battery_technology);

    // Don't print the battery time estimates -- they're wildly inaccurate since
    // this program only takes a single reading of the current.
  }
  return 0;
}
