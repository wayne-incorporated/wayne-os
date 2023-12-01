// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_ADAPTIVE_CHARGING_CONTROLLER_H_
#define POWER_MANAGER_POWERD_POLICY_ADAPTIVE_CHARGING_CONTROLLER_H_

#include <map>
#include <memory>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/important_file_writer.h>
#include <base/time/time.h>
#include <brillo/errors/error.h>
#include <brillo/timers/alarm_timer.h>
#include <featured/feature_library.h>

#include "ml/proto_bindings/ranker_example.pb.h"

#include "power_manager/common/clock.h"
#include "power_manager/common/metrics_constants.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"
#include "power_manager/powerd/policy/backlight_controller.h"
#include "power_manager/powerd/system/dbus_wrapper.h"
#include "power_manager/powerd/system/input_watcher_interface.h"
#include "power_manager/powerd/system/power_supply.h"
#include "power_manager/powerd/system/power_supply_observer.h"
#include "power_manager/proto_bindings/charge_history_state.pb.h"
#include "power_manager/proto_bindings/policy.pb.h"
#include "power_manager/proto_bindings/user_charging_event.pb.h"

namespace power_manager::policy {

// The feature name for slow charging in Adaptive Charging Finch gradual
// rollout.
extern const char kSlowAdaptiveChargingFeatureName[];

class AdaptiveChargingControllerInterface : public system::PowerSupplyObserver {
 public:
  using AdaptiveChargingState = metrics::AdaptiveChargingState;

  class Delegate {
   public:
    // Set the battery sustain state to `lower`, `upper`. `lower` is the charge
    // percent which will be the minimum charge for the battery before it starts
    // charging again. `upper` is the maximum charge. If the battery charge goes
    // over this, it will start to discharge by disabling the AC input current.
    // If `upper` == `lower` and 0 < `upper` < 100, `upper` will be maintained
    // after it is reached by disabling charging (AC will provide current, but
    // won't charge the battery). If both `lower` and `upper` are -1, charge
    // behavior is reverted to the default behavior.
    // Returns true upon success and false otherwise.
    virtual bool SetBatterySustain(int lower, int upper) = 0;

    // Set the battery charge current limit to `limit_mA` in milliamps which
    // will be the charge current used to charge the battery during the slow
    // charging phase of adaptive charging.
    virtual bool SetBatteryChargeLimit(uint32_t limit_mA) = 0;

    // Get the prediction for the next X hours on whether the charger will be
    // connected. Each value in the `result` is added to a sum, one at a time,
    // starting from the first value in `result`. When this value is >=
    // `min_probability_`, the corresponding hour is the prediction for when the
    // charger will be unplugged (except for the last value, which means longer
    // than the number of hours associated with the second to last value).
    // `proto` contains all of the features for the ML model, and `async`
    // indicates if this should not block. Calls `OnPredictionResponse` on
    // success and `OnPredictionFail` otherwise.
    virtual void GetAdaptiveChargingPrediction(
        const assist_ranker::RankerExample& proto, bool async) = 0;

    virtual void GenerateAdaptiveChargingUnplugMetrics(
        const AdaptiveChargingState state,
        const base::TimeTicks& target_time,
        const base::TimeTicks& hold_start_time,
        const base::TimeTicks& hold_end_time,
        const base::TimeTicks& charge_finished_time,
        const base::TimeDelta& time_spent_slow_charging,
        double display_battery_percentage) = 0;
  };

  AdaptiveChargingControllerInterface() = default;
  AdaptiveChargingControllerInterface(
      const AdaptiveChargingControllerInterface&) = delete;
  AdaptiveChargingControllerInterface& operator=(
      const AdaptiveChargingControllerInterface&) = delete;

  ~AdaptiveChargingControllerInterface() override = default;

  // For handling setting changes from the UI settings page or Enterprise
  // policy.
  virtual void HandlePolicyChange(const PowerManagementPolicy& policy) = 0;

  // Runs the prediction before suspending to maximize the delay until we wake
  // in dark resume to re-evaluate charging delays.
  virtual void PrepareForSuspendAttempt() = 0;

  // Reschedules writes for ChargeHistory.
  virtual void HandleFullResume() = 0;

  // Disables Adaptive Charging for shutdown (and hibernate).
  virtual void HandleShutdown() = 0;

  // Function to pass in the results from the Adaptive Charging ml-service.
  // Handles the logic on how to delay charging based on the prediction,
  // `result`.
  virtual void OnPredictionResponse(bool inference_done,
                                    const std::vector<double>& result) = 0;

  // Called upon failure from the Adaptive Charging ml-service.
  virtual void OnPredictionFail(brillo::Error* error) = 0;
};

// Class that records charge history for tracking the start time and duration of
// charging sessions. We only count AC chargers since low power chargers may
// result in discharging of the battery (and thus it's difficult to predict when
// charging will finish).
//
// These values will be used as inputs to the ML model for
// predicting when the charger is unplugged.
// These values are stored in /var/lib/power_manager/. For
// privacy reasons, we floor each time value to a multiple of 15 minutes. Data
// is retained for 30 days.
//
// Example of charge event:
// /var/lib/power_manager/charge_history/charge_events/13296083600000000:
//   "1800000000"
//
// This is a charge event with a 30 minute duration (value stored in
// microseconds). Since we floor all of the timestamps, if the charger is
// connected for less than 15 minutes, it will result in a 0 duration charge
// event. This means that charge events can collide (old event will be
// overwritten).
// The files in /var/lib/power_manager/time_on_ac/ and
// /var/lib/power_manager/time_full_on_ac/ have the same format. These files
// track the total duration for an individual day. The filename is the start of
// the day in microseconds since epoch (UTC). If a charge event spans more than
// 1 day, the duration will be distributed across the corresponding files for
// each day. For example, if 2 hours of charging are equally split across two
// days, with no other charging during those days, the following files will be
// created:
// /var/lib/power_manager/time_on_ac/<day 1>: <1 hour in microseconds>
// /var/lib/power_manager/time_on_ac/<day 2>: <1 hour in microseconds>
//
// If the battery reached full charge after 30 minutes, the following files will
// also be created:
// /var/lib/power_manager/time_full_on_ac/<day 1>: <30 minutes in microseconds>
// /var/lib/power_manager/time_full_on_ac/<day 2>: <1 hour in microseconds>
//
// These files are written when the charger is unplugged. .../time_full_on_ac/
// files are also written when entering a low power state, since those files
// rely on `full_charge_time_`, which is not written to disk.
class ChargeHistory {
 public:
  ChargeHistory();
  ChargeHistory(const ChargeHistory&) = delete;
  ChargeHistory& operator=(const ChargeHistory&) = delete;
  virtual ~ChargeHistory() = default;

  void Init(const system::PowerStatus& status);

  // Must be called before `Init()` to make things simple.
  void set_charge_history_dir_for_testing(const base::FilePath& dir);

  Clock* clock() { return &clock_; }

  // Modifies charge history when the AC charger is plugged/unplugged. Also
  // records the time when the battery reaches full charge.
  void HandlePowerStatusUpdate(const system::PowerStatus& status);

  // Returns the duration on AC within ChargeHistory's retention window.
  base::TimeDelta GetTimeOnAC();

  // Returns the duration on AC with a full charge within ChargeHistory's
  // retention window.
  base::TimeDelta GetTimeFullOnAC();

  // Returns the hold charge duration on AC within ChargeHistory's retention
  // window.
  base::TimeDelta GetHoldTimeOnAC();

  // Returns the charging duration that is the `percentile` percentile for the
  // recorded charge durations. `percentile` should be in the range [0.0, 1.0].
  // A value of 0.5 means that it will return the minimum charge duration that
  // is greater than 50% of the other charge durations. 0.0 will return the
  // shortest duration, and 1.0 will return base::TimeDelta::Max. Any
  // `percentile` value outside of [0.0, 1.0] will fail a CHECK.
  base::TimeDelta GetChargeDurationPercentile(double percentile);

  // Returns the number of days that have charge history recorded.
  int DaysOfHistory();

  // Makes sure that any state that needs to be written to disk before entering
  // a low power state (such as suspend or shutdown) is written.
  void OnEnterLowPowerState();

  // Reschedules pending writes to disk at the next 15 minute aligned time.
  void OnExitLowPowerState();

  // Populate `protobuf` with the internal state of ChargeHistory.
  // Returns true if the state was successfully copied to the protocol buffer,
  // and false if it was not. This can happen if this is called before
  // ChargeHistory has Init called on it.
  bool CopyToProtocolBuffer(ChargeHistoryState* protobuf);

 private:
  // Helper function for `CheckAndFixSystemTimeChange` to correct different
  // `timestamp` values based on the current system time and ticks.
  // Returns true if `timestamp` was corrected, and false if it was not.
  bool CheckAndFixTimestamp(base::Time* timestamp,
                            const base::TimeTicks& ticks,
                            const base::TimeDelta& ticks_offset);

  // Check if system time had a large change, and adjust `full_charge_time_`,
  // `ac_connect_time_` and the charge event file associated with
  // `ac_connect_time_` if there was a large time change.
  void CheckAndFixSystemTimeChange();

  // Calculate and record timestamps to files in `charge_history_dir_` then
  // cache the values in `charge_events_`.
  void UpdateHistory(const system::PowerStatus& status);

  // Record the durations per day for charge directory `dir` and modify the
  // ChargeDays in `days` with the same values.
  void RecordDurations(const base::FilePath& dir,
                       std::map<base::Time, base::TimeDelta>* days,
                       const base::Time& start,
                       base::TimeDelta* total_duration);

  // Read the ChargeDay values from directory `dir` and cache the values in
  // `days`. Also sets `total_duration` to the sum of the durations in the
  // files in `dir`.
  void ReadChargeDaysFromFiles(const base::FilePath& dir,
                               std::map<base::Time, base::TimeDelta>* days,
                               base::TimeDelta* total_duration);

  // Add one ChargeDay for each day since the latest ChargeDay in `days`
  // (does nothing if the latest is today). If there isn't a latest ChargeDay,
  // just append today. Also creates the corresponding files in `dir`.
  //
  // This is used to explicitly track that certain days had no charging. Our
  // heuristic to enable Adaptive Charging relies on 14 days of charge history.
  // If these files aren't set to 0, there's no way to count them when the prior
  // day with a non-zero charge duration leaves the retention window.
  void AddZeroDurationChargeDays(const base::FilePath& dir,
                                 std::map<base::Time, base::TimeDelta>* days);

  // Function to remove all keys from `days` that are older than the retention
  // date and delete the corresponding files.
  void RemoveOldChargeDays(const base::FilePath& dir,
                           std::map<base::Time, base::TimeDelta>* days,
                           base::TimeDelta* total_duration);

  void CreateEmptyChargeEventFile(base::Time start);

  // Remove the oldest charge events until there are fewer than
  // `kMaxChargeEvents`. After this, remove all key, value pairs from
  // `charge_events_` where the end of the charge event is before the retention
  // cutoff.
  void RemoveOldChargeEvents();

  // Remove files older than `kRetentionDays` and reduce the number of charge
  // events to `kMaxChargeEvents` by removing the oldest events.
  void OnRetentionTimerFired();

  // Schedule the `rewrite_timer_` at the next `kChargeHistoryTimeInterval`
  // aligned time. We schedule file rewrites like this for privacy reasons,
  // so that exact timestamps for plug/unplug events don't exist.
  void ScheduleRewrites();

  // This calls WriteNow, then clears out `scheduled_rewrites_`.
  void OnRewriteTimerFired();

  // Write `duration` to the file created from `time` in `dir`, then schedule
  // a rewrite for the same file at the next time multiple of
  // `kChargeHistoryTimeInterval`.
  void WriteDurationToFile(const base::FilePath& dir,
                           base::Time time,
                           base::TimeDelta duration);

  // This returns the duration associated with a day that starts at `day_start`
  // since `start`. `day_start` must be equal to a value returned by
  // `base::Time::UTCMidnight`. For instance, if now is January 10th
  // 00:00:00UTC, `day_start` is January 8th 00:00:00UTC, and `start` is January
  // 8th 12:00:00UTC, this will return base::Hours(12). If `start` is changed to
  // January 7th 00:00:00UTC, this will instead return base::Days(1).
  base::TimeDelta DurationForDay(base::Time start, base::Time day_start);

  // Helper function to floor time values to a multiple of
  // `kChargeHistoryTimeInterval`.
  static base::Time FloorTime(base::Time time);

  // Read The JSON formatted TimeDelta from `path`.
  // Returns true on success and false otherwise.
  static bool ReadTimeDeltaFromFile(const base::FilePath& path,
                                    base::TimeDelta* delta);

  // Write `delta` as a JSON formatted value to `path`.
  // Returns true on success and false otherwise.
  static bool WriteTimeDeltaToFile(const base::FilePath& path,
                                   base::TimeDelta delta);

  // Convert a filename in the JSON Value format to a Time value.
  // Returns true on success and false otherwise.
  static bool JSONFileNameToTime(const base::FilePath& path, base::Time* time);

  // Convert a base::Time value, `time`, to a JSON format filename.
  // Returns true on success and false otherwise.
  static bool TimeToJSONFileName(base::Time time, base::FilePath* path);

  // Delete the JSON format filename converted from `time` in directory `dir`.
  // Crashes if deleting the file fails (not if the JSON conversion fails).
  static void DeleteChargeFile(const base::FilePath& dir, base::Time time);

  // Base directory for Charge History.
  base::FilePath charge_history_dir_;

  // Directory for files that track the amount of time at the hold percent while
  // an AC charger is connected per day. If there's a hold range, start to track
  // time when the lower bound of the range is reached for the first time.
  base::FilePath hold_time_on_ac_dir_;

  // Directory for files that track the amount of time with full charge while an
  // AC charger is connected per day.
  base::FilePath time_full_on_ac_dir_;

  // Directory for files that track the amount of time on an AC charger per day.
  base::FilePath time_on_ac_dir_;

  // Directory for storing charge events, which track the start of charge and
  // duration.
  base::FilePath charge_events_dir_;

  // We schedule replacements on `rewrite_timer_` at
  // `kChargeHistoryTimeInterval` aligned times for privacy reasons; we don't
  // want to leak the exact plug/unplug times accidentally. This contains the
  // paths to be rewritten along with the associated TimeDelta values.
  // The TimeDelta will be serialized out to the FilePath.
  std::map<base::FilePath, base::TimeDelta> scheduled_rewrites_;

  // Timer to schedule files rewrites on for `scheduled_rewrites_`.
  base::RetainingOneShotTimer rewrite_timer_;

  // Timer to schedule removing files due to retention limits.
  base::RepeatingTimer retention_timer_;

  // Clock used to fetch timestamps for `ac_connect_time_`, etc. Timers are not
  // run using this clock. This is used to allow for modifying the time for
  // testing.
  Clock clock_;

  // Cached timestamp for when the charger was connected (if it hasn't been
  // removed yet). Equal to base::Time() (0) if the charger is disconnected.
  // Value is always floored to `kChargeHistoryTimeInterval`.
  base::Time ac_connect_time_;

  // Used for making sure a time change doesn't alter charge durations. For
  // instance, if RTC state is lost, that could result in a large time jump.
  base::TimeTicks ac_connect_ticks_;

  // The duration that AC has been connected on Init (if it was connected then).
  // `ac_connect_ticks_` - `ac_connect_ticks_offset_` is when AC was connected.
  // This is kept separate from `ac_connect_ticks_` to avoid negative
  // base::TimeTicks values, which are not allowed.
  base::TimeDelta ac_connect_ticks_offset_;

  // Timestamp for when we reached full charge for the current charging session.
  // Equal to base::Time() (0) if the charger is disconnected, or we haven't
  // reached full charge yet when the charger is connected.
  // Value is always floored to `kChargeHistoryTimeInterval`.
  base::Time full_charge_time_;

  // Used for making sure a time change doesn't alter time full on AC durations.
  base::TimeTicks full_charge_ticks_;

  // The duration that the system was fully charged while plugged into AC on
  // Init. `full_charge_ticks_` - `full_charge_ticks_offset_` is when the system
  // became fully charged.
  base::TimeDelta full_charge_ticks_offset_;

  // Timestamp for when we started holding/delaying charge. Equal to
  // base::Time() (0) if the charger is disconnected or the battery is actively
  // charging.
  // Value is always floored to `kChargeHistoryTimeInterval`.
  base::Time hold_charge_time_;

  // Used for making sure a time change doesn't alter the hold time on AC
  // durations.
  base::TimeTicks hold_charge_ticks_;

  // Ordered map of charge events, which maps AC charge plug in times to
  // duration of charge. This provides O(logn) addition and removal of charge
  // events (including removal of min and max) where n <= 50.
  std::map<base::Time, base::TimeDelta> charge_events_;

  // TODO(b/241061371): refactor these maps to group them together.
  // Ordered map of days to duration on AC for up to the last 30 days.
  std::map<base::Time, base::TimeDelta> time_on_ac_days_;

  // Ordered map of days to duration on AC with full charge for up to the last
  // 30 days.
  std::map<base::Time, base::TimeDelta> time_full_on_ac_days_;

  // Ordered map of days to duration holding charge while on AC for up to the
  // last 30 days.
  std::map<base::Time, base::TimeDelta> hold_time_on_ac_days_;

  // The duration spent on AC for the charge history currently retained.
  // Value is always floored to `kChargeHistoryTimeInterval`.
  base::TimeDelta duration_on_ac_;

  // The duration spent on AC while fully charged for the charge history
  // currently retained.
  // Value is always floored to `kChargeHistoryTimeInterval`.
  base::TimeDelta duration_full_on_ac_;

  // The duration spent holding charge while on AC for the charge history
  // currently retained in `hold_time_on_ac_dir_`.
  // Value is always floored to `kChargeHistoryTimeInterval`.
  base::TimeDelta hold_duration_on_ac_;

  // Cached external power type. Used to determine if a charge event needs to be
  // created or completed.
  PowerSupplyProperties::ExternalPower cached_external_power_;

  // Whether Init was called yet, which must be called after we're sure that the
  // PowerStatus updated correctly. This is when HandlePowerStatusUpdate is
  // called.
  bool initialized_ = false;

  base::WeakPtrFactory<ChargeHistory> weak_ptr_factory_;
};

class AdaptiveChargingController : public AdaptiveChargingControllerInterface {
 public:
  static constexpr base::TimeDelta kFinishChargingDelay = base::Hours(2);

  // The duration needed to charge a battery from 80% to 100% using slow
  // charging.
  static constexpr base::TimeDelta kFinishSlowChargingDelay = base::Hours(3);

  AdaptiveChargingController();
  AdaptiveChargingController(const AdaptiveChargingController&) = delete;
  AdaptiveChargingController& operator=(const AdaptiveChargingController&) =
      delete;
  ~AdaptiveChargingController() override;

  void Init(Delegate* delegate,
            BacklightController* backlight_controller,
            system::InputWatcherInterface* input_watcher,
            system::PowerSupplyInterface* power_supply,
            system::DBusWrapperInterface* dbus_wrapper,
            feature::PlatformFeaturesInterface* platform_features,
            PrefsInterface* prefs);

  Clock* clock() { return &clock_; }

  void set_recheck_alarm_for_testing(
      std::unique_ptr<brillo::timers::SimpleAlarmTimer> alarm) {
    recheck_alarm_ = std::move(alarm);
  }

  void set_charge_alarm_for_testing(
      std::unique_ptr<brillo::timers::SimpleAlarmTimer> alarm) {
    charge_alarm_ = std::move(alarm);
  }

  void set_charge_delay_for_testing(base::TimeDelta delay) {
    StartChargeAlarm(delay);
  }

  base::TimeDelta get_charge_delay_for_testing() {
    base::TimeDelta finish_charging_delay = slow_charging_enabled_
                                                ? kFinishSlowChargingDelay
                                                : kFinishChargingDelay;
    return target_full_charge_time_ - base::TimeTicks::Now() -
           finish_charging_delay;
  }

  base::TimeTicks get_target_full_charge_time_for_testing() {
    return target_full_charge_time_;
  }

  void set_recheck_delay_for_testing(base::TimeDelta delay) {
    StartRecheckAlarm(delay);
  }

  void set_slow_charging_for_testing(bool enabled) {
    slow_charging_enabled_ = enabled;
  }

  ChargeHistory* get_charge_history_for_testing() { return &charge_history_; }

  // Overridden from AdaptiveChargingControllerInterface:
  void HandlePolicyChange(const PowerManagementPolicy& policy) override;
  void PrepareForSuspendAttempt() override;
  void HandleFullResume() override;
  void HandleShutdown() override;
  void OnPredictionResponse(bool inference_done,
                            const std::vector<double>& result) override;
  void OnPredictionFail(brillo::Error* error) override;

  // Overridden from system::PowerSupplyObserver:
  void OnPowerStatusUpdate() override;

 private:
  // Stop Adaptive Charging for the current charge session. Charging will not be
  // delayed at the |adaptive_charging_percent_| charge until the next time the
  // system is plugged in.
  void HandleChargeNow(dbus::MethodCall* method_call,
                       dbus::ExportedObject::ResponseSender response_sender);

  // Convert and copy `charge_history_` to a protobuf, then return it.
  void HandleGetChargeHistory(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);

  // Sets battery sustain via the `Delegate::SetBatterySustain` callback.
  // Returns true on success and false otherwise.
  bool SetSustain(int64_t lower, int64_t upper);

  // Sets battery charge current limit via the 'Delegate::SetBatteryChargeLimit'
  // callback. Returns true on success and false otherwise.
  bool SetChargeLimit(uint32_t limit_mA);

  // Initiates Adaptive Charging logic, which fetches predictions from the
  // Adaptive Charging ml-service, and delays charging if
  // `adaptive_charging_enabled_` is true. Should not be called a second time if
  // Adaptive Charging is already started.
  // Returns true if Adaptive Charging is started.
  // Battery full is one reason this will return false.
  bool StartAdaptiveCharging(const UserChargingEvent::Event::Reason& reason);

  // Starts the prediction evaluation. Logic is finished via the
  // `OnPredictionResponse` callback.
  void UpdateAdaptiveCharging(const UserChargingEvent::Event::Reason& reason,
                              bool async);

  // Stops Adaptive Charging from delaying charge anymore. Starts the slow
  // charging phase of Adaptive Charging from the set sustain percentage to 100%
  // if the unplug time prediction allows sufficient time for slow charging.
  // Sets the battery charge current limit to 0.1C (10% of battery design
  // capacity).
  void StartSlowCharging();

  // Stops Adaptive Charging from delaying charge anymore. The `recheck_alarm_`
  // and `charge_alarm_` will no longer run unless `StartAdaptiveCharging` is
  // called. When slow charging is enabled, the battery charge current limit
  // will also be reset so if the battery is not fully charged yet, it will now
  // be charged as quickly as possible.
  void StopAdaptiveCharging();

  // Indicates that the prediction code will periodically run for re-evaluating
  // charging delays.
  bool IsRunning();

  // We've reached a display battery percentage where the battery sustainer is
  // active, which in practice means >= `lower` - 1 (`lower` is the last `lower`
  // value passed to `SetSustain`). We subtract 1 since charge can momentarily
  // drop below `lower` with how the battery sustainer code works.
  bool AtHoldPercent(double display_battery_percent);

  // Schedule re-evaluation of the prediction code after `delay`.
  void StartRecheckAlarm(base::TimeDelta delay);

  // Determine the function that gets run when the `charge_alarm_` in
  // `StartChargeAlarm` goes off. If slow charging is enabled,
  // `StartSlowCharging` is run, otherwise `StopAdaptiveCharging` is run.
  void StartChargingToFull();

  // Schedule disabling the battery sustainer and starting charging of the
  // battery again after a `delay`. If slow charging is enabled, the battery
  // starts to charge with a limited charge current. Otherwise, Adaptive
  // Charging is stopped and fast charging commences.
  void StartChargeAlarm(base::TimeDelta delay);

  // Callback for the `recheck_alarm_`. Re-evaluates the prediction.
  void OnRecheckAlarmFired();

  Delegate* delegate_;  // non-owned

  system::PowerSupplyInterface* power_supply_;  // non-owned

  system::DBusWrapperInterface* dbus_wrapper_;  // non-owned

  system::InputWatcherInterface* input_watcher_;  // non-owned

  policy::BacklightController* backlight_controller_;  // non-owned

  feature::PlatformFeaturesInterface* platform_features_;  // non-owned

  PrefsInterface* prefs_;  // non-owned

  // Used for unittesting purposes.
  Clock clock_;

  ChargeHistory charge_history_;

  PowerSupplyProperties::ExternalPower cached_external_power_;

  // For periodically rechecking charger unplug predictions. A SimpleAlarmTimer
  // is used since this will wake the system from suspend (in dark resume) to do
  // this as well.
  std::unique_ptr<brillo::timers::SimpleAlarmTimer> recheck_alarm_ =
      brillo::timers::SimpleAlarmTimer::Create();

  // For charging to full after sustaining `hold_percent_`. A SimpleAlarmTimer
  // is used since we need to wake up the system (in dark resume) to do this as
  // well.
  std::unique_ptr<brillo::timers::SimpleAlarmTimer> charge_alarm_ =
      brillo::timers::SimpleAlarmTimer::Create();

  // Current target for when we plan to fully charge the battery.
  base::TimeTicks target_full_charge_time_;

  // The time when we started delaying charge via the battery sustainer. Used
  // for reporting metrics.
  base::TimeTicks hold_percent_start_time_;

  // The time when we stopped delaying charge. Used for reporting metrics.
  base::TimeTicks hold_percent_end_time_;

  // The time when we reached fill charge. Used for reporting metrics.
  base::TimeTicks charge_finished_time_;

  // The duration spent slow charging. Used for reporting metrics.
  base::TimeDelta time_spent_slow_charging_;

  // Interval for rechecking the prediction, and modifying whether charging is
  // delayed based on that prediction.
  base::TimeDelta recheck_alarm_interval_;

  // Tracks the specific state of Adaptive Charging for determining what
  // functionality to perform, as well as reporting to UMA.
  //
  // States are as follows:
  //
  // * ACTIVE - Adaptive Charging is running and is delaying charging or may
  //   delay charging in the future.
  //
  // * SLOWCHARGE - Adaptive Charging is running and slow charging has
  //   commenced.
  //
  // * INACTIVE - Adaptive Charging is enabled, but it stopped delaying
  //   charging or never started.
  //
  // * HEURISTIC_DISABLED - Adaptive Charging's heuristic (separate from the ML
  //   model) determined that it should not delay charge.
  //
  // * USER_CANCELED - User stopped Adaptive Charging by clicking the "Charge
  //   Now" button.
  //
  // * USER_DISABLED - User does not have the Adaptive Charging feature enabled
  //   (but it is supported), but the heuristic check for enabling passes.
  //
  // * SHUTDOWN - The system has initiated shutdown, so starting any new
  //   Adaptive Charging logic is prevented (metrics may still be reported on AC
  //   unplug).
  //
  // * NOT_SUPPORTED - EC functionality required for Adaptive Charging does not
  //   exist on this platform, but the heuristic check for enabling passes.
  AdaptiveChargingState state_;

  // Whether we should report the AdaptiveChargingTimeToFull metric, which
  // should only be done if charging started with the battery charge less than
  // `hold_percent_`.
  bool report_charge_time_;

  // The default upper percent for the battery sustainer. Not used if the
  // battery has a higher display battery percentage when the AC is connected.
  int64_t hold_percent_;

  // Used for setting the lower percent for the battery sustainer, with `upper`
  // - `hold_delta_percent_`. Used to work around "singing" capacitors, which
  // are on some systems. When there is no current going to or from the battery,
  // the system load from the AC power circuit can drop low enough that makes
  // the capacitors vibrate at an audible frequency. By always having the
  // battery charge or discharge (AC current is disabled in this case), we can
  // avoid the "singing" of these capacitors.
  int64_t hold_delta_percent_;

  // The battery percent to display while delaying charge. Will be
  // `hold_percent_` or the display battery percentage when battery sustainer
  // starts if it's higher than `hold_percent_`.
  int64_t display_percent_;

  // The ML service returns a vector of nine doubles in the range (0.0, 1.0).
  // These doubles sum to 1.0. Each value in this vector is added to a sum, one
  // at a time. When that sum is greater than or equal to this value, the index
  // of the last value to be added is the number of hours we predict the charger
  // will remain plugged in, except for the last index, which corresponds with
  // 8+ hours.
  double min_probability_;

  // The percentile for ChargeHistory::charge_events_ durations to use as the
  // maximum delay for Adaptive Charging (minus `kFinishChargingDelay`). Used as
  // a personalized heuristic to make Adaptive Charging less aggressive, thus
  // making it more likely users will unplug with a full charge if possible.
  double max_delay_percentile_;

  // Whether Adaptive Charging logic was started on AC plug in, or when it was
  // enabled. Currently set to false if the battery was full under these
  // conditions. This can be true even if Adaptive Charging isn't enabled, and
  // we're just reporting metrics.
  bool started_;

  // Whether the Battery Sustainer is currently set for Adaptive Charging.
  bool is_sustain_set_;

  // The following two booleans control how this class behaves via the following
  // table:
  // enabled | supported |
  // 1       | 1         | Evaluate predictions and delay charging.
  //                       `state` is one of: ACTIVE, SLOWCHARGING, INACTIVE,
  //                       HEURISTIC_DISABLED, or USER_CANCELED.
  // 1       | 0         | Scenario does not exist.
  // 0       | 1         | Evaluate predictions but do not delay charging.
  //                       `state_` is set to HEURISTIC_DISABLED, USER_DISABLED
  //                       or SHUTDOWN.
  // 0       | 0         | Evaluate predictions but do not delay charging.
  //                       `state_` is set to NOT_SUPPORTED or SHUTDOWN.
  //
  // Whether Adaptive Charging will delay charging. Predictions are still
  // evaluated if this is false.
  bool adaptive_charging_enabled_;

  // Whether the system supports battery sustainer on the EC. Explicitly checked
  // for during `Init`. Adaptive Charging cannot be enabled unless this is true.
  bool adaptive_charging_supported_;

  // Whether slow charging with a limited battery charge current will occur as a
  // part of Adaptive Charging.
  bool slow_charging_enabled_;

  // Whether the system supports limiting the battery charge current on the EC.
  // Explicitly checked for during `Init`. Slow charging in Adaptive Charging
  // cannot be enabled unless this is true.
  bool slow_charging_supported_;

  base::WeakPtrFactory<AdaptiveChargingController> weak_ptr_factory_;
};

}  // namespace power_manager::policy

#endif  // POWER_MANAGER_POWERD_POLICY_ADAPTIVE_CHARGING_CONTROLLER_H_
