// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdio>
#include <memory>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/message_loop/message_pump_type.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/flag_helper.h>
#include <libec/ec_command_factory.h>

#include "power_manager/common/battery_percentage_converter.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"
#include "power_manager/powerd/system/dbus_wrapper_stub.h"
#include "power_manager/powerd/system/power_supply.h"
#include "power_manager/powerd/system/udev_stub.h"

namespace {

// Number of retry attempts for reading the PowerStatus.
static const int kPowerRefreshRetries = 3;

// Escapes |str| so it can be printed as a value.
std::string Escape(const std::string& str) {
  std::string out;
  base::ReplaceChars(str, "\n", " ", &out);
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  brillo::FlagHelper::Init(
      argc, argv,
      "Print power supply information.\n"
      "\n"
      "This program shares powerd's code for reading information from\n"
      "/sys/class/power_supply. It prints data in a format that can be\n"
      "parsed by tests and by other programs.\n"
      "\n"
      "Each line of output consists of a name, followed by a single space,\n"
      "followed by a value, followed by a newline. String values are\n"
      "untrimmed and may contain whitespace or be empty, but any newlines\n"
      "are replaced with spaces.");
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
  const power_manager::system::PowerStatus status =
      power_supply.GetPowerStatus();

  // Do not change the format of this output.
  printf("line_power_connected %d\n", status.line_power_on);
  printf("line_power_type %s\n", Escape(status.line_power_type).c_str());
  printf("line_power_current %0.2f\n", status.line_power_current);
  printf("battery_present %d\n", status.battery_is_present);
  printf("battery_percent %0.2f\n", status.battery_percentage);
  printf("battery_display_percent %0.2f\n", status.display_battery_percentage);
  printf("battery_charge %0.2f\n", status.battery_charge);
  printf("battery_charge_full %0.2f\n", status.battery_charge_full);
  printf("battery_charge_full_design %0.2f\n",
         status.battery_charge_full_design);
  printf("battery_current %0.2f\n", status.battery_current);
  printf("battery_energy %0.2f\n", status.battery_energy);
  printf("battery_energy_rate %0.2f\n", status.battery_energy_rate);
  printf("battery_voltage %0.2f\n", status.battery_voltage);
  printf("battery_status %s\n", Escape(status.battery_status_string).c_str());
  printf("battery_discharging %d\n",
         status.battery_state ==
             power_manager::PowerSupplyProperties_BatteryState_DISCHARGING);

  return 0;
}
