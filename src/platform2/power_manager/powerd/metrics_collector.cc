// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/metrics_collector.h"

#include <stdint.h>

#include <algorithm>
#include <cmath>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>

#include "policy/adaptive_charging_controller.h"
#include "power_manager/common/metrics_constants.h"
#include "power_manager/common/metrics_sender.h"
#include "power_manager/common/prefs.h"
#include "power_manager/common/tracing.h"
#include "power_manager/common/util.h"
#include "power_manager/powerd/policy/backlight_controller.h"

namespace power_manager {

using system::PowerStatus;

namespace metrics {
namespace {

// Generates the histogram name under which dark resume wake duration metrics
// are logged for the dark resume triggered by |wake_reason|.
std::string WakeReasonToHistogramName(const std::string& wake_reason) {
  return std::string("Power.DarkResumeWakeDurationMs.").append(wake_reason);
}

// Returns true if port |index| exists in |status| and has a connected dedicated
// source or dual-role device.
bool ChargingPortConnected(const PowerStatus& status, size_t index) {
  if (index >= status.ports.size())
    return false;

  const PowerStatus::Port::Role role = status.ports[index].role;
  return role == PowerStatus::Port::Role::DEDICATED_SOURCE ||
         role == PowerStatus::Port::Role::DUAL_ROLE;
}

// Returns a value describing which power ports are connected.
ConnectedChargingPorts GetConnectedChargingPorts(const PowerStatus& status) {
  // More values should be added here if we ship systems with more than two
  // ports.
  if (status.ports.size() > 2u)
    return ConnectedChargingPorts::TOO_MANY_PORTS;

  const bool port1_connected = ChargingPortConnected(status, 0);
  const bool port2_connected = ChargingPortConnected(status, 1);
  if (port1_connected && port2_connected)
    return ConnectedChargingPorts::PORT1_PORT2;
  else if (port1_connected)
    return ConnectedChargingPorts::PORT1;
  else if (port2_connected)
    return ConnectedChargingPorts::PORT2;
  else
    return ConnectedChargingPorts::NONE;
}

}  // namespace

// static
constexpr char MetricsCollector::kAcpiPC10ResidencyPath[];
constexpr char MetricsCollector::kBigCoreS0ixResidencyPath[];
constexpr char MetricsCollector::kSmallCoreS0ixResidencyPath[];
constexpr base::TimeDelta MetricsCollector::KS0ixOverheadTime;

SingleValueResidencyReader::SingleValueResidencyReader(
    const base::FilePath& path)
    : path_(path) {}

base::TimeDelta SingleValueResidencyReader::ReadResidency() {
  uint64_t value;
  // If |path_| is empty, reading the file will fail gracefully. There is no
  // early-exit as |IdleResidencyTracker| update functions perform that function
  // so no point in adding extra checks.
  const bool success = util::ReadUint64File(path_, &value);

  if (!success) {
    PLOG(WARNING) << "Failed to read residency from " << path_.value();
  }
  // base::Microseconds() will fail for INT64_MAX, however that's unlikely to
  // ever happen.
  return success ? base::Microseconds(value) : InvalidValue;
}

IdleResidencyTracker::IdleResidencyTracker(
    std::shared_ptr<ResidencyReader> reader)
    : reader_(reader),
      pre_suspend_(ResidencyReader::InvalidValue),
      post_resume_(ResidencyReader::InvalidValue) {}

bool IdleResidencyTracker::IsValid() {
  return !pre_suspend_.is_negative() && !post_resume_.is_negative();
}

base::TimeDelta IdleResidencyTracker::PreSuspend() const {
  return pre_suspend_;
}

base::TimeDelta IdleResidencyTracker::PostResume() const {
  return post_resume_;
}

void IdleResidencyTracker::UpdatePreSuspend() {
  pre_suspend_ = reader_ != nullptr ? reader_->ReadResidency()
                                    : ResidencyReader::InvalidValue;
}

void IdleResidencyTracker::UpdatePostResume() {
  post_resume_ = reader_ != nullptr ? reader_->ReadResidency()
                                    : ResidencyReader::InvalidValue;
}

std::string MetricsCollector::AppendPowerSourceToEnumName(
    const std::string& enum_name, PowerSource power_source) {
  return enum_name +
         (power_source == PowerSource::AC ? kAcSuffix : kBatterySuffix);
}

std::string MetricsCollector::AppendPrivacyScreenStateToEnumName(
    const std::string& enum_name,
    const privacy_screen::PrivacyScreenSetting_PrivacyScreenState& state) {
  switch (state) {
    case privacy_screen::PrivacyScreenSetting_PrivacyScreenState_DISABLED:
      return enum_name + kPrivacyScreenDisabled;
    case privacy_screen::PrivacyScreenSetting_PrivacyScreenState_ENABLED:
      return enum_name + kPrivacyScreenEnabled;
    default:
      NOTREACHED()
          << "Will not send metrics for unhandled privacy screen state "
          << static_cast<int>(state);
      return enum_name;
  }
}

// static
int MetricsCollector::GetExpectedResidencyPercent(
    const base::TimeDelta& reference_time,
    const base::TimeDelta& actual_residency,
    const base::TimeDelta& overhead) {
  base::TimeDelta expected_delta = reference_time - overhead;
  double expected_residency = expected_delta.InMicrosecondsF();
  // Sanity check to prevent divide by zero undefined behavior below. This might
  // happen when overhead == reference_time (including == 0). Also catch cases
  // where overhead is larger than reference_time.
  if (expected_residency <= 0)
    return 0;
  int residency_percent = static_cast<int>(
      round((actual_residency.InMicrosecondsF() * 100.0) / expected_residency));
  // Guard against >100% case when |actual_residency| goes over the predicted
  // |overhead|.
  return std::min(100, residency_percent);
}

MetricsCollector::MetricsCollector() = default;

MetricsCollector::~MetricsCollector() = default;

void MetricsCollector::Init(
    PrefsInterface* prefs,
    policy::BacklightController* display_backlight_controller,
    policy::BacklightController* keyboard_backlight_controller,
    const PowerStatus& power_status,
    bool first_run_after_boot) {
  prefs_ = prefs;
  display_backlight_controller_ = display_backlight_controller;
  keyboard_backlight_controller_ = keyboard_backlight_controller;
  last_power_status_ = power_status;

  if (first_run_after_boot) {
    // Enum to avoid exponential histogram's varyingly-sized buckets.
    SendEnumMetricWithPowerSource(
        kBatteryRemainingAtBootName,
        static_cast<int>(round(last_power_status_.battery_percentage)),
        kMaxPercent);
  }

  if (display_backlight_controller_ || keyboard_backlight_controller_) {
    generate_backlight_metrics_timer_.Start(
        FROM_HERE, kBacklightLevelInterval, this,
        &MetricsCollector::GenerateBacklightLevelMetrics);
  }

  if (display_backlight_controller_) {
    display_backlight_controller_->RegisterAmbientLightResumeMetricsHandler(
        base::BindRepeating(
            &MetricsCollector::GenerateAmbientLightResumeMetrics,
            base::Unretained(this)));
  }

  bool pref_val = false;
  suspend_to_idle_ = prefs_->GetBool(kSuspendToIdlePref, &pref_val) && pref_val;

  base::FilePath s0ix_residency_path;
  // S0ix residency related configuration.
  if (base::PathExists(
          GetPrefixedFilePath(base::FilePath(kBigCoreS0ixResidencyPath)))) {
    s0ix_residency_path =
        GetPrefixedFilePath(base::FilePath(kBigCoreS0ixResidencyPath));
  } else if (base::PathExists(GetPrefixedFilePath(
                 base::FilePath(kSmallCoreS0ixResidencyPath)))) {
    s0ix_residency_path =
        GetPrefixedFilePath(base::FilePath(kSmallCoreS0ixResidencyPath));
  }
  // For devices with |kBigCoreS0ixResidencyPath|, the default range is a
  // little complicated. |kBigCoreS0ixResidencyPath| reports the time spent in
  // S0ix by reading SLP_S0_RES (32 bit) register. This register increments
  // once for every *_PMC_SLP_S0_RES_COUNTER_STEP microseconds spent in S0ix
  // (see drivers/platform/x86/intel/pmc/core.h in Linux kernel sources for
  // exact resolution). The value read from this 32 bit register is first cast
  // to u64 and then multiplied by the counter resolution to get a microsecond
  // granularity. For |kBigCoreS0ixResidencyPath| a resolution upper bound of
  // 100 microseconds is used to discard samples on counter roll-over.
  if (s0ix_residency_path ==
      GetPrefixedFilePath(base::FilePath(kBigCoreS0ixResidencyPath))) {
    max_s0ix_residency_ = base::Microseconds(100 * (uint64_t)UINT32_MAX);
  }

  base::FilePath pc10_residency_path;
  // PC10 residency related configuration.
  if (base::PathExists(
          GetPrefixedFilePath(base::FilePath(kAcpiPC10ResidencyPath)))) {
    pc10_residency_path =
        GetPrefixedFilePath(base::FilePath(kAcpiPC10ResidencyPath));
  }

  // Finally create residency trackers for accessible counters.
  // For unavailable counters, leave the tracker uninitialized (with a nullptr
  // ResidencyReader).
  if (!s0ix_residency_path.empty()) {
    residency_trackers_[IdleState::S0ix] = IdleResidencyTracker(
        std::make_shared<SingleValueResidencyReader>(s0ix_residency_path));
  }
  if (!pc10_residency_path.empty()) {
    residency_trackers_[IdleState::PC10] = IdleResidencyTracker(
        std::make_shared<SingleValueResidencyReader>(pc10_residency_path));
  }
}

void MetricsCollector::HandleScreenDimmedChange(
    bool dimmed, base::TimeTicks last_user_activity_time) {
  if (dimmed) {
    base::TimeTicks now = clock_.GetCurrentTime();
    screen_dim_timestamp_ = now;
    last_idle_event_timestamp_ = now;
    last_idle_timedelta_ = now - last_user_activity_time;
  } else {
    screen_dim_timestamp_ = base::TimeTicks();
  }
}

void MetricsCollector::HandleScreenOffChange(
    bool off, base::TimeTicks last_user_activity_time) {
  if (off) {
    base::TimeTicks now = clock_.GetCurrentTime();
    screen_off_timestamp_ = now;
    last_idle_event_timestamp_ = now;
    last_idle_timedelta_ = now - last_user_activity_time;
  } else {
    screen_off_timestamp_ = base::TimeTicks();
  }
}

void MetricsCollector::HandleSessionStateChange(SessionState state) {
  if (state == session_state_)
    return;

  session_state_ = state;

  switch (state) {
    case SessionState::STARTED:
      session_start_time_ = clock_.GetCurrentTime();
      if (!last_power_status_.line_power_on)
        IncrementNumOfSessionsPerChargeMetric();
      if (last_power_status_.battery_is_present) {
        // Enum to avoid exponential histogram's varyingly-sized buckets.
        SendEnumMetricWithPowerSource(
            kBatteryRemainingAtStartOfSessionName,
            static_cast<int>(round(last_power_status_.battery_percentage)),
            kMaxPercent);
      }
      break;
    case SessionState::STOPPED: {
      if (last_power_status_.battery_is_present) {
        // Enum to avoid exponential histogram's varyingly-sized buckets.
        SendEnumMetricWithPowerSource(
            kBatteryRemainingAtEndOfSessionName,
            static_cast<int>(round(last_power_status_.battery_percentage)),
            kMaxPercent);
      }

      SendMetric(kLengthOfSessionName,
                 (clock_.GetCurrentTime() - session_start_time_).InSeconds(),
                 kLengthOfSessionMin, kLengthOfSessionMax, kDefaultBuckets);

      if (display_backlight_controller_) {
        SendMetric(kNumberOfAlsAdjustmentsPerSessionName,
                   display_backlight_controller_
                       ->GetNumAmbientLightSensorAdjustments(),
                   kNumberOfAlsAdjustmentsPerSessionMin,
                   kNumberOfAlsAdjustmentsPerSessionMax, kDefaultBuckets);
        SendMetricWithPowerSource(
            kUserBrightnessAdjustmentsPerSessionName,
            display_backlight_controller_->GetNumUserAdjustments(),
            kUserBrightnessAdjustmentsPerSessionMin,
            kUserBrightnessAdjustmentsPerSessionMax, kDefaultBuckets);
      }
      break;
    }
  }
}

void MetricsCollector::HandlePowerStatusUpdate(const PowerStatus& status) {
  const bool previously_on_line_power = last_power_status_.line_power_on;
  const bool previously_using_unknown_type =
      previously_on_line_power &&
      system::GetPowerSupplyTypeMetric(last_power_status_.line_power_type) ==
          PowerSupplyType::OTHER;

  last_power_status_ = status;

  // Charge stats.
  if (status.line_power_on && !previously_on_line_power) {
    GenerateNumOfSessionsPerChargeMetric();
    if (status.battery_is_present) {
      // Enum to avoid exponential histogram's varyingly-sized buckets.
      SendEnumMetric(kBatteryRemainingWhenChargeStartsName,
                     static_cast<int>(round(status.battery_percentage)),
                     kMaxPercent);
      SendEnumMetric(kBatteryChargeHealthName,
                     static_cast<int>(round(100.0 * status.battery_charge_full /
                                            status.battery_charge_full_design)),
                     kBatteryChargeHealthMax);

      std::string metric_name = kBatteryCapacityName;
      SendMetric(metric_name + kBatteryCapacityActualSuffix,
                 static_cast<int>(round(1000.0 * status.battery_energy_full)),
                 kBatteryCapacityMin, kBatteryCapacityMax, kDefaultBuckets);

      SendMetric(
          metric_name + kBatteryCapacityDesignSuffix,
          static_cast<int>(round(1000.0 * status.battery_energy_full_design)),
          kBatteryCapacityMin, kBatteryCapacityMax, kDefaultBuckets);
    }
  } else if (!status.line_power_on && previously_on_line_power) {
    if (session_state_ == SessionState::STARTED)
      IncrementNumOfSessionsPerChargeMetric();
  }

  // Power supply details.
  if (status.line_power_on) {
    const PowerSupplyType type =
        system::GetPowerSupplyTypeMetric(status.line_power_type);
    if (type == PowerSupplyType::OTHER && !previously_using_unknown_type)
      LOG(WARNING) << "Unknown power supply type " << status.line_power_type;
    SendEnumMetric(kPowerSupplyTypeName, static_cast<int>(type),
                   static_cast<int>(PowerSupplyType::MAX));

    // Sent as enums to avoid exponential histogram's exponentially-sized
    // buckets.
    SendEnumMetric(kPowerSupplyMaxVoltageName,
                   static_cast<int>(round(status.line_power_max_voltage)),
                   kPowerSupplyMaxVoltageMax);
    SendEnumMetric(kPowerSupplyMaxPowerName,
                   static_cast<int>(round(status.line_power_max_voltage *
                                          status.line_power_max_current)),
                   kPowerSupplyMaxPowerMax);
  }

  SendEnumMetric(kConnectedChargingPortsName,
                 static_cast<int>(GetConnectedChargingPorts(status)),
                 static_cast<int>(ConnectedChargingPorts::MAX));

  GenerateBatteryDischargeRateMetric();
  GenerateBatteryDischargeRateWhileSuspendedMetric();

  SendEnumMetric(kBatteryInfoSampleName,
                 static_cast<int>(BatteryInfoSampleResult::READ),
                 static_cast<int>(BatteryInfoSampleResult::MAX));
  // TODO(derat): Continue sending BAD in some situations? Remove this metric
  // entirely?
  SendEnumMetric(kBatteryInfoSampleName,
                 static_cast<int>(BatteryInfoSampleResult::GOOD),
                 static_cast<int>(BatteryInfoSampleResult::MAX));
}

void MetricsCollector::HandleShutdown(ShutdownReason reason) {
  SendEnumMetric(kShutdownReasonName, static_cast<int>(reason),
                 static_cast<int>(kShutdownReasonMax));
}

void MetricsCollector::HandlePrivacyScreenStateChange(
    const privacy_screen::PrivacyScreenSetting_PrivacyScreenState& state) {
  if (state == privacy_screen_state_)
    return;

  privacy_screen_state_ = state;
}

void MetricsCollector::PrepareForSuspend() {
  battery_energy_before_suspend_ = last_power_status_.battery_energy;
  on_line_power_before_suspend_ = last_power_status_.line_power_on;
  time_before_suspend_ = clock_.GetCurrentBootTime();
  for (auto& tracker : residency_trackers_)
    tracker.UpdatePreSuspend();
  GenerateRuntimeS0ixMetrics();
}

void MetricsCollector::HandleResume(int num_suspend_attempts, bool hibernated) {
  last_suspend_was_hibernate_ = hibernated;
  SendMetric(hibernated ? kHibernateAttemptsBeforeSuccessName
                        : kSuspendAttemptsBeforeSuccessName,
             num_suspend_attempts, kSuspendAttemptsMin, kSuspendAttemptsMax,
             kSuspendAttemptsBuckets);
  // Report the discharge rate in response to the next
  // OnPowerStatusUpdate() call.
  report_battery_discharge_rate_while_suspended_ = true;
  time_after_resume_ = clock_.GetCurrentBootTime();
  for (auto& tracker : residency_trackers_)
    tracker.UpdatePostResume();
  if (suspend_to_idle_ && !hibernated)
    GenerateS2IdleS0ixMetrics();
}

void MetricsCollector::HandleCanceledSuspendRequest(int num_suspend_attempts,
                                                    bool hibernate) {
  SendMetric(hibernate ? kHibernateAttemptsBeforeCancelName
                       : kSuspendAttemptsBeforeCancelName,
             num_suspend_attempts, kSuspendAttemptsMin, kSuspendAttemptsMax,
             kSuspendAttemptsBuckets);
}

void MetricsCollector::GenerateDarkResumeMetrics(
    const std::vector<policy::Suspender::DarkResumeInfo>& wake_durations,
    base::TimeDelta suspend_duration) {
  if (suspend_duration.InSeconds() <= 0)
    return;

  // We want to get metrics even if the system suspended for less than an hour
  // so we scale the number of wakes up.
  static const int kSecondsPerHour = 60 * 60;
  const int64_t wakeups_per_hour =
      wake_durations.size() * kSecondsPerHour / suspend_duration.InSeconds();
  SendMetric(kDarkResumeWakeupsPerHourName, wakeups_per_hour,
             kDarkResumeWakeupsPerHourMin, kDarkResumeWakeupsPerHourMax,
             kDefaultBuckets);

  for (const auto& pair : wake_durations) {
    // Send aggregated dark resume duration metric.
    SendMetric(kDarkResumeWakeDurationMsName, pair.second.InMilliseconds(),
               kDarkResumeWakeDurationMsMin, kDarkResumeWakeDurationMsMax,
               kDefaultBuckets);
    // Send wake reason-specific dark resume duration metric.
    SendMetric(WakeReasonToHistogramName(pair.first),
               pair.second.InMilliseconds(), kDarkResumeWakeDurationMsMin,
               kDarkResumeWakeDurationMsMax, kDefaultBuckets);
  }
}

void MetricsCollector::GenerateUserActivityMetrics() {
  if (last_idle_event_timestamp_.is_null())
    return;

  base::TimeTicks current_time = clock_.GetCurrentTime();
  base::TimeDelta event_delta = current_time - last_idle_event_timestamp_;
  base::TimeDelta total_delta = event_delta + last_idle_timedelta_;
  last_idle_event_timestamp_ = base::TimeTicks();

  SendMetricWithPowerSource(kIdleName, total_delta.InMilliseconds(), kIdleMin,
                            kIdleMax, kDefaultBuckets);

  if (!screen_dim_timestamp_.is_null()) {
    base::TimeDelta dim_event_delta = current_time - screen_dim_timestamp_;
    SendMetricWithPowerSource(
        kIdleAfterDimName, dim_event_delta.InMilliseconds(), kIdleAfterDimMin,
        kIdleAfterDimMax, kDefaultBuckets);
    screen_dim_timestamp_ = base::TimeTicks();
  }
  if (!screen_off_timestamp_.is_null()) {
    base::TimeDelta screen_off_event_delta =
        current_time - screen_off_timestamp_;
    SendMetricWithPowerSource(
        kIdleAfterScreenOffName, screen_off_event_delta.InMilliseconds(),
        kIdleAfterScreenOffMin, kIdleAfterScreenOffMax, kDefaultBuckets);
    screen_off_timestamp_ = base::TimeTicks();
  }
}

void MetricsCollector::GenerateBacklightLevelMetrics() {
  TRACE_EVENT("power", "MetricsCollector::GenerateBacklightLevelMetrics");
  if (!screen_dim_timestamp_.is_null() || !screen_off_timestamp_.is_null())
    return;

  double percent = 0.0;
  if (display_backlight_controller_ &&
      display_backlight_controller_->GetBrightnessPercent(&percent)) {
    // Enum to avoid exponential histogram's varyingly-sized buckets.
    SendEnumMetricWithPowerSource(kBacklightLevelName, lround(percent),
                                  kMaxPercent);
    SendEnumMetricWithPrivacyScreenStatePowerSource(
        kBacklightLevelName, lround(percent), kMaxPercent);
  }
  if (keyboard_backlight_controller_ &&
      keyboard_backlight_controller_->GetBrightnessPercent(&percent)) {
    // Enum to avoid exponential histogram's varyingly-sized buckets.
    SendEnumMetric(kKeyboardBacklightLevelName, lround(percent), kMaxPercent);
  }
}

void MetricsCollector::GenerateDimEventMetrics(const DimEvent sample) {
  SendEnumMetricWithPowerSource(kDimEvent, static_cast<int>(sample),
                                static_cast<int>(DimEvent::MAX));
}

void MetricsCollector::GenerateLockEventMetrics(const LockEvent sample) {
  SendEnumMetricWithPowerSource(kLockEvent, static_cast<int>(sample),
                                static_cast<int>(LockEvent::MAX));
}

void MetricsCollector::GenerateHpsEventDurationMetrics(
    const std::string& event_name, base::TimeDelta duration) {
  SendMetric(event_name, duration.InSeconds(), kHpsEventDurationMin,
             kHpsEventDurationMax, kDefaultBuckets);
}

void MetricsCollector::HandlePowerButtonEvent(ButtonState state) {
  switch (state) {
    case ButtonState::DOWN:
      // Just keep track of the time when the button was pressed.
      if (!last_power_button_down_timestamp_.is_null()) {
        LOG(ERROR) << "Got power-button-down event while button was already "
                   << "down";
      }
      last_power_button_down_timestamp_ = clock_.GetCurrentTime();
      break;
    case ButtonState::UP: {
      // Metrics are sent after the button is released.
      if (last_power_button_down_timestamp_.is_null()) {
        LOG(ERROR) << "Got power-button-up event while button was already up";
      } else {
        base::TimeDelta delta =
            clock_.GetCurrentTime() - last_power_button_down_timestamp_;
        last_power_button_down_timestamp_ = base::TimeTicks();
        SendMetric(kPowerButtonDownTimeName, delta.InMilliseconds(),
                   kPowerButtonDownTimeMin, kPowerButtonDownTimeMax,
                   kDefaultBuckets);
      }
      break;
    }
    case ButtonState::REPEAT:
      // Ignore repeat events if we get them.
      break;
  }
}

void MetricsCollector::SendPowerButtonAcknowledgmentDelayMetric(
    base::TimeDelta delay) {
  SendMetric(kPowerButtonAcknowledgmentDelayName, delay.InMilliseconds(),
             kPowerButtonAcknowledgmentDelayMin,
             kPowerButtonAcknowledgmentDelayMax, kDefaultBuckets);
}

bool MetricsCollector::SendMetricWithPowerSource(
    const std::string& name, int sample, int min, int max, int num_buckets) {
  const std::string full_name = AppendPowerSourceToEnumName(
      name, last_power_status_.line_power_on ? PowerSource::AC
                                             : PowerSource::BATTERY);
  return SendMetric(full_name, sample, min, max, num_buckets);
}

bool MetricsCollector::SendEnumMetricWithPowerSource(const std::string& name,
                                                     int sample,
                                                     int max) {
  const std::string full_name = AppendPowerSourceToEnumName(
      name, last_power_status_.line_power_on ? PowerSource::AC
                                             : PowerSource::BATTERY);
  return SendEnumMetric(full_name, sample, max);
}

bool MetricsCollector::SendEnumMetricWithPrivacyScreenStatePowerSource(
    const std::string& name, int sample, int max) {
  privacy_screen::PrivacyScreenSetting_PrivacyScreenState state =
      privacy_screen_state_;
  switch (state) {
    case privacy_screen::PrivacyScreenSetting_PrivacyScreenState_DISABLED:
    case privacy_screen::PrivacyScreenSetting_PrivacyScreenState_ENABLED:
      return SendEnumMetricWithPowerSource(
          AppendPrivacyScreenStateToEnumName(name, state), sample, max);
    default:
      return true;
  }
}

void MetricsCollector::GenerateBatteryDischargeRateMetric() {
  // The battery discharge rate metric is relevant and collected only
  // when running on battery.
  if (!last_power_status_.battery_is_present ||
      last_power_status_.line_power_on)
    return;

  // Converts the discharge rate from W to mW.
  int rate =
      static_cast<int>(round(last_power_status_.battery_energy_rate * 1000));
  if (rate <= 0)
    return;

  // Ensures that the metric is not generated too frequently.
  if (!last_battery_discharge_rate_metric_timestamp_.is_null() &&
      (clock_.GetCurrentTime() -
       last_battery_discharge_rate_metric_timestamp_) <
          kBatteryDischargeRateInterval) {
    return;
  }

  if (SendMetric(kBatteryDischargeRateName, rate, kBatteryDischargeRateMin,
                 kBatteryDischargeRateMax, kDefaultDischargeBuckets))
    last_battery_discharge_rate_metric_timestamp_ = clock_.GetCurrentTime();

  double low_battery_shutdown_percent = 0.0;
  prefs_->GetDouble(kLowBatteryShutdownPercentPref,
                    &low_battery_shutdown_percent);

  int battery_life_actual =
      static_cast<int>(round(60 * last_power_status_.battery_energy_full /
                             last_power_status_.battery_energy_rate *
                             (100 - low_battery_shutdown_percent) / 100.0));
  int battery_life_design = static_cast<int>(
      round(60 * last_power_status_.battery_energy_full_design /
            last_power_status_.battery_energy_rate *
            (100 - low_battery_shutdown_percent) / 100.0));

  std::string metrics_name = kBatteryLifeName;
  SendMetric(metrics_name + kBatteryCapacityActualSuffix, battery_life_actual,
             kBatteryLifeMin, kBatteryLifeMax, kDefaultDischargeBuckets);
  SendMetric(metrics_name + kBatteryCapacityDesignSuffix, battery_life_design,
             kBatteryLifeMin, kBatteryLifeMax, kDefaultDischargeBuckets);
}

void MetricsCollector::GenerateBatteryDischargeRateWhileSuspendedMetric() {
  // Do nothing unless this is the first time we're called after resuming.
  if (!report_battery_discharge_rate_while_suspended_)
    return;
  report_battery_discharge_rate_while_suspended_ = false;

  if (!last_power_status_.battery_is_present || on_line_power_before_suspend_ ||
      last_power_status_.line_power_on)
    return;

  base::TimeDelta elapsed_time =
      clock_.GetCurrentBootTime() - time_before_suspend_;
  if (elapsed_time < kBatteryDischargeRateWhileSuspendedMinSuspend)
    return;

  double discharged_watt_hours =
      battery_energy_before_suspend_ - last_power_status_.battery_energy;
  double discharge_rate_watts =
      discharged_watt_hours / (elapsed_time.InSecondsF() / 3600);

  // Maybe the charger was connected while the system was suspended but
  // disconnected before it resumed.
  if (discharge_rate_watts < 0.0)
    return;

  SendMetric(last_suspend_was_hibernate_
                 ? kBatteryDischargeRateWhileHibernatedName
                 : kBatteryDischargeRateWhileSuspendedName,
             static_cast<int>(round(discharge_rate_watts * 1000)),
             kBatteryDischargeRateWhileSuspendedMin,
             kBatteryDischargeRateWhileSuspendedMax, kDefaultDischargeBuckets);

  // We don't care about battery life while hibernate.
  if (last_suspend_was_hibernate_)
    return;

  if (discharge_rate_watts <= 0.0)
    return;

  std::string metrics_name = kBatteryLifeWhileSuspendedName;
  SendMetric(metrics_name + kBatteryCapacityActualSuffix,
             static_cast<int>(round(last_power_status_.battery_energy_full /
                                    discharge_rate_watts)),
             kBatteryLifeWhileSuspendedMin, kBatteryLifeWhileSuspendedMax,
             kDefaultDischargeBuckets);
  SendMetric(
      metrics_name + kBatteryCapacityDesignSuffix,
      static_cast<int>(round(last_power_status_.battery_energy_full_design /
                             discharge_rate_watts)),
      kBatteryLifeWhileSuspendedMin, kBatteryLifeWhileSuspendedMax,
      kDefaultDischargeBuckets);
}

void MetricsCollector::GenerateAdaptiveChargingUnplugMetrics(
    const AdaptiveChargingState state,
    const base::TimeTicks& target_time,
    const base::TimeTicks& hold_start_time,
    const base::TimeTicks& hold_end_time,
    const base::TimeTicks& charge_finished_time,
    const base::TimeDelta& time_spent_slow_charging,
    double display_battery_percentage) {
  base::TimeTicks now = clock_.GetCurrentBootTime();
  std::string metric_name = kAdaptiveChargingMinutesDeltaName;
  std::string state_suffix = "";
  std::string time_suffix = "";
  std::string type_suffix = "";

  switch (state) {
    case AdaptiveChargingState::ACTIVE:
    case AdaptiveChargingState::SLOWCHARGE:
    case AdaptiveChargingState::INACTIVE:
      state_suffix = kAdaptiveChargingStateActiveSuffix;
      break;
    case AdaptiveChargingState::HEURISTIC_DISABLED:
      state_suffix = kAdaptiveChargingStateHeuristicDisabledSuffix;
      break;
    case AdaptiveChargingState::USER_CANCELED:
      state_suffix = kAdaptiveChargingStateUserCanceledSuffix;
      break;
    case AdaptiveChargingState::USER_DISABLED:
      state_suffix = kAdaptiveChargingStateUserDisabledSuffix;
      break;
    case AdaptiveChargingState::SHUTDOWN:
      state_suffix = kAdaptiveChargingStateShutdownSuffix;
      break;
    case AdaptiveChargingState::NOT_SUPPORTED:
      state_suffix = kAdaptiveChargingStateNotSupportedSuffix;
      break;
    default:
      LOG(ERROR) << "Invalid Adaptive Charging State for reporting to UMA: "
                 << static_cast<int>(state);
  }

  base::TimeDelta delta = now - target_time;
  if (delta.is_negative()) {
    time_suffix = kAdaptiveChargingLateSuffix;
    delta = delta.magnitude();
  } else {
    time_suffix = kAdaptiveChargingEarlySuffix;
  }

  SendMetric(metric_name + state_suffix + time_suffix, delta.InMinutes(),
             kAdaptiveChargingDeltaMin, kAdaptiveChargingDeltaMax,
             kDefaultBuckets);

  base::TimeDelta total_charge_time = charge_finished_time - hold_end_time;
  if (time_spent_slow_charging == base::TimeDelta()) {
    type_suffix = kAdaptiveChargingTypeNormalChargingSuffix;
  } else if (total_charge_time - time_spent_slow_charging > base::Seconds(1)) {
    type_suffix = kAdaptiveChargingTypeMixedChargingSuffix;
  } else {
    type_suffix = kAdaptiveChargingTypeSlowChargingSuffix;
  }

  SendEnumMetric(kAdaptiveChargingBatteryPercentageOnUnplugName + type_suffix,
                 lround(display_battery_percentage), kMaxPercent);

  if (charge_finished_time != base::TimeTicks()) {
    SendMetric(kAdaptiveChargingMinutesToFullName + type_suffix,
               (charge_finished_time - hold_end_time).InMinutes(),
               kAdaptiveChargingMinutesToFullMin,
               kAdaptiveChargingMinutesToFullMax, kDefaultBuckets);
  }

  base::TimeDelta delay_time = hold_start_time == base::TimeTicks()
                                   ? base::TimeDelta()
                                   : hold_end_time - hold_start_time;
  SendMetric(kAdaptiveChargingMinutesDelayName, delay_time.InMinutes(),
             kAdaptiveChargingMinutesMin, kAdaptiveChargingMinutesMax,
             kAdaptiveChargingMinutesBuckets);

  base::TimeDelta available_time = hold_start_time == base::TimeTicks()
                                       ? base::TimeDelta()
                                       : now - hold_start_time;
  SendMetric(kAdaptiveChargingMinutesAvailableName, available_time.InMinutes(),
             kAdaptiveChargingMinutesMin, kAdaptiveChargingMinutesMax,
             kAdaptiveChargingMinutesBuckets);

  metric_name = kAdaptiveChargingDelayDeltaName;

  // Compute the available time minus the time reserved for charging first. If
  // this is negative, the available hold time is 0.
  base::TimeDelta slow_charging_delay =
      policy::AdaptiveChargingController::kFinishSlowChargingDelay;
  base::TimeDelta normal_charging_delay =
      policy::AdaptiveChargingController::kFinishChargingDelay;
  if (available_time >= slow_charging_delay) {
    delta = available_time - slow_charging_delay;
  } else {
    delta = available_time - normal_charging_delay;
  }

  if (delta.is_negative())
    delta = base::TimeDelta();

  delta -= delay_time;
  if (delta.is_negative()) {
    time_suffix = kAdaptiveChargingLateSuffix;
    delta = delta.magnitude();
  } else {
    time_suffix = kAdaptiveChargingEarlySuffix;
  }

  SendMetric(metric_name + state_suffix + time_suffix, delta.InMinutes(),
             kAdaptiveChargingDeltaMin, kAdaptiveChargingDeltaMax,
             kDefaultBuckets);

  metric_name = kAdaptiveChargingMinutesFullOnACName;
  delta = charge_finished_time == base::TimeTicks()
              ? base::TimeDelta()
              : now - charge_finished_time;
  SendMetric(metric_name + state_suffix, delta.InMinutes(),
             kAdaptiveChargingMinutesMin, kAdaptiveChargingMinutesMax,
             kAdaptiveChargingMinutesBuckets);
}

void MetricsCollector::IncrementNumOfSessionsPerChargeMetric() {
  int64_t num = 0;
  prefs_->GetInt64(kNumSessionsOnCurrentChargePref, &num);
  num = std::max(num, static_cast<int64_t>(0));
  prefs_->SetInt64(kNumSessionsOnCurrentChargePref, num + 1);
}

void MetricsCollector::GenerateNumOfSessionsPerChargeMetric() {
  int64_t sample = 0;
  prefs_->GetInt64(kNumSessionsOnCurrentChargePref, &sample);
  if (sample <= 0)
    return;

  sample = std::min(sample, static_cast<int64_t>(kNumOfSessionsPerChargeMax));
  prefs_->SetInt64(kNumSessionsOnCurrentChargePref, 0);
  SendMetric(kNumOfSessionsPerChargeName, sample, kNumOfSessionsPerChargeMin,
             kNumOfSessionsPerChargeMax, kDefaultBuckets);
}

void MetricsCollector::GenerateAmbientLightResumeMetrics(int lux) {
  SendMetric(kAmbientLightOnResumeName, lux, kAmbientLightOnResumeMin,
             kAmbientLightOnResumeMax, kDefaultBuckets);
}

void MetricsCollector::GenerateS2IdleS0ixMetrics() {
  // This method should be invoked only when suspend to idle is enabled.
  CHECK(suspend_to_idle_);

  IdleResidencyTracker& s0ix = residency_trackers_[IdleState::S0ix];

  // If S0ix residency reading was not successful, we have no way to track the
  // residency during suspend.
  if (!s0ix.IsValid())
    return;

  const base::TimeDelta s0ix_residency = s0ix.PostResume() - s0ix.PreSuspend();

  // If the counter overflowed during suspend, then residency delta is not
  // useful anymore because we have no way to read the precise residency counter
  // resolution.
  // We'll loose a single sample per |max_s0ix_residency_| which is at minimum
  // ~5 days.
  if (s0ix_residency.is_negative())
    return;

  const base::TimeDelta time_in_suspend =
      clock_.GetCurrentBootTime() - time_before_suspend_;

  // If we spent more time in suspend than the max residency that
  // |s0ix_residency_path_| can report, then the residency counter is
  // not reliable anymore.
  // At most we'll loose a single sample per |max_s0ix_residency_| which is
  // at minimum ~5 days.
  if (time_in_suspend > max_s0ix_residency_)
    return;

  // If the device woke from suspend before |KS0ixOverheadTime|, then the
  // CPUs might not have entered S0ix. Let us not complain nor generate UMA
  // metrics.
  if (time_in_suspend <= KS0ixOverheadTime)
    return;

  int s0ix_residency_percent =
      GetExpectedResidencyPercent(time_in_suspend, s0ix_residency);
  // If we spent less than 90% of time in S0ix, log a warning. This can help
  // debugging feedback reports that complain about low battery life.
  if (s0ix_residency_percent < 90) {
    LOG(WARNING) << "Device spent around " << time_in_suspend.InSeconds()
                 << " secs in suspend, but only " << s0ix_residency.InSeconds()
                 << " secs in S0ix";
  }

  // Enum to avoid exponential histogram's varyingly-sized buckets.
  SendEnumMetric(kS0ixResidencyRateName, s0ix_residency_percent, kMaxPercent);
}

void MetricsCollector::GenerateRuntimeS0ixMetrics() {
  IdleResidencyTracker& s0ix = residency_trackers_[IdleState::S0ix];
  IdleResidencyTracker& pc10 = residency_trackers_[IdleState::PC10];

  // If either S0ix or PC10 residency reading was not successful, we have no way
  // to track the runtime residency.
  if (!s0ix.IsValid() || !pc10.IsValid())
    return;

  const base::TimeDelta s0ix_residency = s0ix.PreSuspend() - s0ix.PostResume();
  const base::TimeDelta pc10_residency = pc10.PreSuspend() - pc10.PostResume();

  // If the counter overflowed during suspend, then residency delta is not
  // useful anymore because we have no way to read the precise residency counter
  // resolution.
  // We'll loose a single sample per counter. For S0ix it is
  // |max_s0ix_residency_| which is at minimum ~5 days.
  if (s0ix_residency.is_negative() || pc10_residency.is_negative())
    return;

  // Calculate the time between |HandleResume| and |PrepareForSuspend|. This
  // includes one round of |residency_trackers_| update which will be taken into
  // account by |kRuntimeS0ixOverheadTime| later.
  const base::TimeDelta time_in_resume =
      time_before_suspend_ - time_after_resume_;

  // If user initiated suspend less than |kRuntimeS0ixOverheadTime| after resume
  // don't report such metric. This is fine as the overhead time is in range of
  // microseconds which would mean that user didn't want to resume the system
  // anyway.
  if (time_in_resume <= kRuntimeS0ixOverheadTime)
    return;

  // Guard against a very unlikely case of a counter roll-over using
  // |max_s0ix_residency_| as a safety lower-bound which gives us a minimum of
  // ~5 days in runtime.
  if (time_in_resume > max_s0ix_residency_)
    return;

  // Additionally measure how much time is spent in PC10 compared to the
  // runtime. This should give us an estimate on potential power-savings if S0ix
  // is enabled.
  // Take the expected overhead into account. Worst case (if there wasn't any),
  // the impact should be negligible (runtime is usually several orders of
  // magnitude longer).
  int pc10_residency_percent = GetExpectedResidencyPercent(
      time_in_resume, pc10_residency, kRuntimeS0ixOverheadTime);

  // Enum to avoid exponential histogram's varyingly-sized buckets.
  SendEnumMetric(kPC10RuntimeResidencyRateName, pc10_residency_percent,
                 kMaxPercent);

  // Report time spent in S0ix only if device actually spent some time in PC10.
  // Otherwise there would be no difference between devices that spent no time
  // in S0ix and ones which couldn't have (due to PC10 residency being 0).
  if (pc10_residency_percent > 0) {
    // Since runtime may last quite long compared to time spent in idle,
    // calculate instead how much time SoC spent in S0ix compared to the PC10
    // (which is a pre-requisite for runtime S0ix).
    // Do not apply overhead because it's safer to round-down this metric when
    // PC10 residency is small.
    int pc10_in_s0ix_percent = GetExpectedResidencyPercent(
        pc10_residency, s0ix_residency, base::Microseconds(0));

    // Enum to avoid exponential histogram's varyingly-sized buckets.
    SendEnumMetric(kPC10inS0ixRuntimeResidencyRateName, pc10_in_s0ix_percent,
                   kMaxPercent);
  }
}

base::FilePath MetricsCollector::GetPrefixedFilePath(
    const base::FilePath& file_path) const {
  if (prefix_path_for_testing_.empty())
    return file_path;
  DCHECK(file_path.IsAbsolute());
  return prefix_path_for_testing_.Append(file_path.value().substr(1));
}

}  // namespace metrics
}  // namespace power_manager
