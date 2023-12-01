// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/common/power_constants.h"

#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>

namespace power_manager {

// Prefs.
const char kLowBatteryShutdownTimePref[] = "low_battery_shutdown_time_s";
const char kLowBatteryShutdownPercentPref[] = "low_battery_shutdown_percent";
const char kPluggedDimMsPref[] = "plugged_dim_ms";
const char kPluggedQuickDimMsPref[] = "plugged_quick_dim_ms";
const char kPluggedQuickLockMsPref[] = "plugged_quick_lock_ms";
const char kPluggedOffMsPref[] = "plugged_off_ms";
const char kPluggedSuspendMsPref[] = "plugged_suspend_ms";
const char kUnpluggedDimMsPref[] = "unplugged_dim_ms";
const char kUnpluggedQuickDimMsPref[] = "unplugged_quick_dim_ms";
const char kUnpluggedQuickLockMsPref[] = "unplugged_quick_lock_ms";
const char kUnpluggedOffMsPref[] = "unplugged_off_ms";
const char kUnpluggedSuspendMsPref[] = "unplugged_suspend_ms";
const char kSendFeedbackIfUndimmedPref[] = "send_feedback_if_undimmed";
const char kDisableIdleSuspendPref[] = "disable_idle_suspend";
const char kFactoryModePref[] = "factory_mode";
const char kUseLidPref[] = "use_lid";
const char kPreferredLidDevicePref[] = "preferred_lid_device";
const char kDetectHoverPref[] = "detect_hover";
const char kRetrySuspendMsPref[] = "retry_suspend_ms";
const char kRetrySuspendAttemptsPref[] = "retry_suspend_attempts";
const char kMinVisibleBacklightLevelPref[] = "min_visible_backlight_level";
const char kInstantTransitionsBelowMinLevelPref[] =
    "instant_transitions_below_min_level";
const char kAvoidSuspendWhenHeadphoneJackPluggedPref[] =
    "avoid_suspend_when_headphone_jack_plugged";
const char kWakeupInputPref[] = "wakeup_input_device_names";
const char kPowerSupplyFullFactorPref[] = "power_supply_full_factor";
const char kInternalBacklightMaxNitsPref[] = "internal_backlight_max_nits";
const char kInternalBacklightAlsStepsPref[] = "internal_backlight_als_steps";
const char kInternalBacklightNoAlsAcBrightnessPref[] =
    "internal_backlight_no_als_ac_brightness";
const char kInternalBacklightNoAlsBatteryBrightnessPref[] =
    "internal_backlight_no_als_battery_brightness";
const char kKeyboardBacklightAlsStepsPref[] = "keyboard_backlight_als_steps";
const char kKeyboardBacklightUserStepsPref[] = "keyboard_backlight_user_steps";
const char kKeyboardBacklightNoAlsBrightnessPref[] =
    "keyboard_backlight_no_als_brightness";
const char kKeyboardBacklightKeepOnMsPref[] = "keyboard_backlight_keep_on_ms";
const char kKeyboardBacklightKeepOnDuringVideoMsPref[] =
    "keyboard_backlight_keep_on_during_video_ms";
const char kAlsSmoothingConstantPref[] = "als_smoothing_constant";
const char kRequireUsbInputDeviceToSuspendPref[] =
    "require_usb_input_device_to_suspend";
const char kBatteryPollIntervalPref[] = "battery_poll_interval_ms";
const char kBatteryPollIntervalInitialPref[] =
    "battery_poll_interval_initial_ms";
const char kBatteryStabilizedAfterStartupMsPref[] =
    "battery_stabilized_after_startup_ms";
const char kBatteryStabilizedAfterLinePowerConnectedMsPref[] =
    "battery_stabilized_after_line_power_connected_ms";
const char kBatteryStabilizedAfterLinePowerDisconnectedMsPref[] =
    "battery_stabilized_after_line_power_disconnected_ms";
const char kBatteryStabilizedAfterResumeMsPref[] =
    "battery_stabilized_after_resume_ms";
const char kMultipleBatteriesPref[] = "multiple_batteries";
const char kHasBarreljackPref[] = "has_barreljack";
const char kMaxCurrentSamplesPref[] = "max_current_samples";
const char kMaxChargeSamplesPref[] = "max_charge_samples";
const char kUsbMinAcWattsPref[] = "usb_min_ac_watts";
const char kChargingPortsPref[] = "charging_ports";
const char kAdaptiveChargingAlarmSecPref[] = "adaptive_charging_alarm_sec";
const char kAdaptiveChargingHoldPercentPref[] =
    "adaptive_charging_hold_percent";
const char kAdaptiveChargingHoldDeltaPercentPref[] =
    "adaptive_charging_hold_delta_percent";
const char kAdaptiveChargingMinProbabilityPref[] =
    "adaptive_charging_min_probability";
const char kAdaptiveChargingEnabledPref[] = "adaptive_charging_enabled";
const char kSlowAdaptiveChargingEnabledPref[] =
    "slow_adaptive_charging_enabled";
const char kTurnOffScreenTimeoutMsPref[] = "turn_off_screen_timeout_ms";
const char kDisableDarkResumePref[] = "disable_dark_resume";
const char kDisableHibernatePref[] = "disable_hibernate";
const char kLowerPowerFromSuspendSecPref[] = "lower_power_from_suspend_sec";
const char kIgnoreExternalPolicyPref[] = "ignore_external_policy";
const char kNumSessionsOnCurrentChargePref[] = "num_sessions_on_current_charge";
const char kHasAmbientLightSensorPref[] = "has_ambient_light_sensor";
const char kAllowAmbientEQ[] = "allow_ambient_eq";
const char kHasChargeControllerPref[] = "has_charge_controller";
const char kHasKeyboardBacklightPref[] = "has_keyboard_backlight";
const char kExternalDisplayOnlyPref[] = "external_display_only";
const char kLegacyPowerButtonPref[] = "legacy_power_button";
const char kManualEventlogAddPref[] = "manual_eventlog_add";
const char kUseCrasPref[] = "use_cras";
const char kTpmCounterSuspendThresholdPref[] = "tpm_counter_suspend_threshold";
const char kTpmStatusIntervalSecPref[] = "tpm_status_interval_sec";
const char kSuspendToIdlePref[] = "suspend_to_idle";
const char kHasMachineQuirksPref[] = "has_machine_quirks";
const char kSuspendToIdleListPref[] = "suspend_to_idle_models";
const char kSuspendPreventionListPref[] = "suspend_prevention_models";
const char kSetTransmitPowerPreferFarForProximityPref[] =
    "set_transmit_power_prefer_far_for_proximity";
const char kWifiTransmitPowerModeForStaticDevicePref[] =
    "wifi_transmit_power_mode_for_static_device";
const char kSetWifiTransmitPowerForTabletModePref[] =
    "set_wifi_transmit_power_for_tablet_mode";
const char kSetWifiTransmitPowerForProximityPref[] =
    "set_wifi_transmit_power_for_proximity";
const char kSetWifiTransmitPowerForActivityProximityPref[] =
    "set_wifi_transmit_power_for_activity_proximity";
const char kSetCellularTransmitPowerForTabletModePref[] =
    "set_cellular_transmit_power_for_tablet_mode";
const char kSetCellularTransmitPowerForProximityPref[] =
    "set_cellular_transmit_power_for_proximity";
const char kSetCellularTransmitPowerForActivityProximityPref[] =
    "set_cellular_transmit_power_for_activity_proximity";
const char kSetCellularTransmitPowerDprGpioPref[] =
    "set_cellular_transmit_power_dpr_gpio";
const char kUseModemManagerForDynamicSARPref[] =
    "use_modemmanager_for_dynamic_sar";
const char kUseMultiPowerLevelDynamicSARPref[] =
    "use_multi_power_level_dynamic_sar";
const char kSetCellularTransmitPowerLevelMappingPref[] =
    "set_cellular_transmit_power_level_mapping";
const char kSetCellularRegulatoryDomainMappingPref[] =
    "set_cellular_regulatory_domain_mapping";
const char kSetDefaultProximityStateHighPref[] =
    "set_default_proximity_state_high";
const char kUseRegulatoryDomainForDynamicSARPref[] =
    "use_regulatory_domain_for_dynamic_sar";
const char kEnableConsoleDuringSuspendPref[] = "enable_console_during_suspend";
const char kMaxDarkSuspendDelayTimeoutMsPref[] =
    "max_dark_suspend_delay_timeout_ms";
const char kSuspendModePref[] = "suspend_mode";
const char kWakeOnDpPref[] = "wake_on_dp";
const char kSmartDischargeToZeroHrPref[] = "smart_discharge_to_zero_hr";
const char kCutoffPowerUaPref[] = "cutoff_power_ua";
const char kHibernatePowerUaPref[] = "hibernate_power_ua";
const char kDeferExternalDisplayTimeoutPref[] =
    "defer_external_display_timeout";
const char kExternalAmbientLightSensorPref[] = "external_ambient_light_sensor";
const char kExternalBacklightAlsStepsPref[] = "external_backlight_als_steps";

// This pref is incomplete. Prefs based on it are defined by other packages
// populating them.
const char kSuspendFreezerDepsPrefix[] = "suspend_freezer_deps_";

// Miscellaneous constants.
const char kCrosFpInputDevName[] = "cros_fp_input";
const char kInternalBacklightPath[] = "/sys/class/backlight";
const char kInternalBacklightPattern[] = "*";
const char kKeyboardBacklightPath[] = "/sys/class/leds";
const char kKeyboardBacklightPattern[] = "*:kbd_backlight";
const char kKeyboardBacklightUdevSubsystem[] = "leds";
const char kPowerStatusPath[] = "/sys/class/power_supply";
const char kSetuidHelperPath[] = "/usr/bin/powerd_setuid_helper";
const char kBusServiceName[] = "org.freedesktop.DBus";
const char kBusServicePath[] = "/org/freedesktop/DBus";
const char kBusInterface[] = "org.freedesktop.DBus";
const char kBusNameOwnerChangedSignal[] = "NameOwnerChanged";
const char kPowerWakeup[] = "power/wakeup";
const double kEpsilon = 0.001;
const base::TimeDelta kFastBacklightTransition = base::Milliseconds(200);
const base::TimeDelta kSlowBacklightTransition = base::Seconds(2);
const char kInputUdevSubsystem[] = "input";
const char kCrosECLightName[] = "cros-ec-light";
const char kAcpiAlsName[] = "acpi-als";

std::string PowerSourceToString(PowerSource source) {
  switch (source) {
    case PowerSource::AC:
      return "AC";
    case PowerSource::BATTERY:
      return "battery";
  }
  NOTREACHED() << "Unhandled power source " << static_cast<int>(source);
  return base::StringPrintf("unknown (%d)", static_cast<int>(source));
}

std::string LidStateToString(LidState state) {
  switch (state) {
    case LidState::OPEN:
      return "open";
    case LidState::CLOSED:
      return "closed";
    case LidState::NOT_PRESENT:
      return "not present";
  }
  NOTREACHED() << "Unhandled lid state " << static_cast<int>(state);
  return base::StringPrintf("unknown (%d)", static_cast<int>(state));
}

std::string TabletModeToString(TabletMode mode) {
  switch (mode) {
    case TabletMode::ON:
      return "on";
    case TabletMode::OFF:
      return "off";
    case TabletMode::UNSUPPORTED:
      return "unsupported";
  }
  NOTREACHED() << "Unhandled tablet mode " << static_cast<int>(mode);
  return base::StringPrintf("unknown (%d)", static_cast<int>(mode));
}

std::string UserProximityToString(UserProximity proximity) {
  switch (proximity) {
    case UserProximity::NEAR:
      return "near";
    case UserProximity::FAR:
      return "far";
    case UserProximity::UNKNOWN:
      return "unknown";
  }
  NOTREACHED() << "Unhandled user proximity " << static_cast<int>(proximity);
  return base::StringPrintf("unknown (%d)", static_cast<int>(proximity));
}

std::string RadioTransmitPowerToString(RadioTransmitPower power) {
  switch (power) {
    case RadioTransmitPower::LOW:
      return "low";
    case RadioTransmitPower::MEDIUM:
      return "medium";
    case RadioTransmitPower::HIGH:
      return "high";
    case RadioTransmitPower::UNSPECIFIED:
      return "unspecified";
  }
  NOTREACHED() << "Unhandled Radio transmit power " << static_cast<int>(power);
  return base::StringPrintf("unknown (%d)", static_cast<int>(power));
}

std::string RegulatoryDomainToString(CellularRegulatoryDomain domain) {
  switch (domain) {
    case CellularRegulatoryDomain::FCC:
      return "FCC";
    case CellularRegulatoryDomain::ISED:
      return "ISED";
    case CellularRegulatoryDomain::CE:
      return "CE";
    case CellularRegulatoryDomain::MIC:
      return "MIC";
    case CellularRegulatoryDomain::KCC:
      return "KCC";
    case CellularRegulatoryDomain::UNKNOWN:
      return "UNKNOWN";
  }
  NOTREACHED() << "Unhandled Regulatory Domain " << static_cast<int>(domain);
  return base::StringPrintf("unknown (%d)", static_cast<int>(domain));
}

std::string SessionStateToString(SessionState state) {
  switch (state) {
    case SessionState::STOPPED:
      return "stopped";
    case SessionState::STARTED:
      return "started";
  }
  NOTREACHED() << "Unhandled session state " << static_cast<int>(state);
  return base::StringPrintf("unknown (%d)", static_cast<int>(state));
}

std::string DisplayModeToString(DisplayMode mode) {
  switch (mode) {
    case DisplayMode::NORMAL:
      return "normal";
    case DisplayMode::PRESENTATION:
      return "presentation";
  }
  NOTREACHED() << "Unhandled display mode " << static_cast<int>(mode);
  return base::StringPrintf("unknown (%d)", static_cast<int>(mode));
}

std::string ButtonStateToString(ButtonState state) {
  switch (state) {
    case ButtonState::UP:
      return "up";
    case ButtonState::DOWN:
      return "down";
    case ButtonState::REPEAT:
      return "repeat";
  }
  NOTREACHED() << "Unhandled button state " << static_cast<int>(state);
  return base::StringPrintf("unknown (%d)", static_cast<int>(state));
}

std::string ShutdownReasonToString(ShutdownReason reason) {
  // These are passed as SHUTDOWN_REASON arguments to an initctl command to
  // switch to runlevel 0 (shutdown) or 6 (reboot). Don't change these strings
  // without checking that other Upstart jobs aren't depending on them.
  switch (reason) {
    case ShutdownReason::USER_REQUEST:
      return "user-request";
    case ShutdownReason::STATE_TRANSITION:
      return "state-transition";
    case ShutdownReason::LOW_BATTERY:
      return "low-battery";
    case ShutdownReason::SUSPEND_FAILED:
      return "suspend-failed";
    case ShutdownReason::SHUTDOWN_FROM_SUSPEND:
      return "shutdown-from-suspend";
    case ShutdownReason::SYSTEM_UPDATE:
      return "system-update";
    case ShutdownReason::OTHER_REQUEST_TO_POWERD:
      return "other-request-to-powerd";
    case ShutdownReason::HIBERNATE_FAILED:
      return "hibernate-failed";
  }
  NOTREACHED() << "Unhandled shutdown reason " << static_cast<int>(reason);
  return "unknown";
}

std::string WifiRegDomainToString(WifiRegDomain domain) {
  switch (domain) {
    case WifiRegDomain::FCC:
      return "FCC";
    case WifiRegDomain::EU:
      return "EU";
    case WifiRegDomain::REST_OF_WORLD:
      return "Rest-of-World";
    case WifiRegDomain::NONE:
      return "None";
  }
  NOTREACHED() << "Unhandled WiFi reg domain " << static_cast<int>(domain);
  return "unknown";
}

}  // namespace power_manager
