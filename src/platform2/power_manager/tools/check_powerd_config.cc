// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdio>
#include <cstdlib>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/format_macros.h>
#include <base/logging.h>
#include <base/message_loop/message_pump_type.h>
#include <base/notreached.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/flag_helper.h>

#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"

int main(int argc, char* argv[]) {
  DEFINE_bool(ambient_light_sensor, false,
              "Print the number of ambient light sensors supported; exit with "
              "success if any ambient light sensor support is enabled");
  DEFINE_bool(hover_detection, false,
              "Exit with success if hover detection is enabled");
  DEFINE_bool(internal_backlight_ambient_light_steps, false,
              "Print the value of the internal_backlight_als_steps pref to "
              "stdout");
  DEFINE_bool(keyboard_backlight, false,
              "Exit with success if keyboard backlight support is enabled");
  DEFINE_bool(low_battery_shutdown_percent, false,
              "Print the percent-based low-battery shutdown threshold (in "
              "[0.0, 100.0]) to stdout");
  DEFINE_bool(low_battery_shutdown_time, false,
              "Print the time-based low-battery shutdown threshold (in "
              "seconds) to stdout");
  DEFINE_bool(set_wifi_transmit_power, false,
              "Exit with success if support for setting WiFi transmit power is "
              "enabled");
  DEFINE_bool(suspend_to_idle, false,
              "Exit with success if \"freeze\" (rather than \"mem\") will be "
              "written to /sys/power/state when suspending");
  DEFINE_bool(defer_external_display_timeout, false,
              "Prints the external display timeout deferral time (in seconds) "
              "to stdout");

  brillo::FlagHelper::Init(argc, argv,
                           "Check the device's power-related configuration");

  base::AtExitManager at_exit_manager;
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  logging::SetMinLogLevel(logging::LOGGING_WARNING);

  if (FLAGS_ambient_light_sensor + FLAGS_hover_detection +
          FLAGS_internal_backlight_ambient_light_steps +
          FLAGS_keyboard_backlight + FLAGS_low_battery_shutdown_percent +
          FLAGS_low_battery_shutdown_time + FLAGS_set_wifi_transmit_power +
          FLAGS_suspend_to_idle + FLAGS_defer_external_display_timeout !=
      1) {
    fprintf(stderr, "Exactly one flag must be set\n");
    exit(1);
  }

  power_manager::Prefs prefs;
  CHECK(prefs.Init(power_manager::Prefs::GetDefaultStore(),
                   power_manager::Prefs::GetDefaultSources()));

  if (FLAGS_ambient_light_sensor) {
    int64_t num_als = 0;
    prefs.GetInt64(power_manager::kHasAmbientLightSensorPref, &num_als);
    printf("%" PRId64 "\n", num_als);
    exit(num_als > 0 ? 0 : 1);
  } else if (FLAGS_hover_detection) {
    bool hover_enabled = false;
    prefs.GetBool(power_manager::kDetectHoverPref, &hover_enabled);
    exit(hover_enabled ? 0 : 1);
  } else if (FLAGS_internal_backlight_ambient_light_steps) {
    std::string steps;
    prefs.GetString(power_manager::kInternalBacklightAlsStepsPref, &steps);
    printf("%s\n", steps.c_str());
    exit(0);
  } else if (FLAGS_keyboard_backlight) {
    bool backlight_enabled = false;
    prefs.GetBool(power_manager::kHasKeyboardBacklightPref, &backlight_enabled);
    exit(backlight_enabled ? 0 : 1);
  } else if (FLAGS_low_battery_shutdown_percent) {
    double percent = 0.0;
    prefs.GetDouble(power_manager::kLowBatteryShutdownPercentPref, &percent);
    printf("%.1f\n", percent);
    exit(0);
  } else if (FLAGS_low_battery_shutdown_time) {
    int64_t sec = 0;
    double p = 0.0;
    // Match system::PowerSupply's logic: a time-based threshold is ignored if a
    // percent-based threshold is set.
    if (!prefs.GetDouble(power_manager::kLowBatteryShutdownPercentPref, &p))
      prefs.GetInt64(power_manager::kLowBatteryShutdownTimePref, &sec);
    printf("%" PRId64 "\n", sec);
    exit(0);
  } else if (FLAGS_set_wifi_transmit_power) {
    // Check for dynamic (tablet) or proximity configurations.
    bool set_wifi_transmit_power = false;
    prefs.GetBool(power_manager::kSetWifiTransmitPowerForTabletModePref,
                  &set_wifi_transmit_power);
    if (!set_wifi_transmit_power) {
      prefs.GetBool(power_manager::kSetWifiTransmitPowerForProximityPref,
                    &set_wifi_transmit_power);
    }
    if (set_wifi_transmit_power) {
      exit(0);
    }
    // If not present, check for static device configuration.
    std::string wifi_transmit_power_mode_for_static_device;
    prefs.GetString(power_manager::kWifiTransmitPowerModeForStaticDevicePref,
                    &wifi_transmit_power_mode_for_static_device);
    exit(!wifi_transmit_power_mode_for_static_device.empty() ? 0 : 1);
  } else if (FLAGS_suspend_to_idle) {
    bool suspend_to_idle = false;
    prefs.GetBool(power_manager::kSuspendToIdlePref, &suspend_to_idle);
    exit(suspend_to_idle ? 0 : 1);
  } else if (FLAGS_defer_external_display_timeout) {
    int64_t defer_external_display_timeout = 0;
    prefs.GetInt64(power_manager::kDeferExternalDisplayTimeoutPref,
                   &defer_external_display_timeout);
    printf("%" PRId64 "\n", defer_external_display_timeout);
    exit(0);
  } else {
    NOTREACHED();
    exit(1);
  }
}
