// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/adaptive_charging_controller.h"

#include <algorithm>
#include <functional>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <base/containers/contains.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/json/json_file_value_serializer.h>
#include <base/json/values_util.h>
#include <base/run_loop.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <featured/fake_platform_features.h>
#include <gtest/gtest.h>

#include "power_manager/common/fake_prefs.h"
#include "power_manager/powerd/policy/backlight_controller_stub.h"
#include "power_manager/powerd/system/dbus_wrapper_stub.h"
#include "power_manager/powerd/system/input_watcher_stub.h"
#include "power_manager/powerd/system/power_supply_stub.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::policy {

namespace {
const int64_t kBatterySustainDisabled = -1;
const uint32_t kSlowChargingDisabled = std::numeric_limits<uint32_t>::max();

// Make this different from the default in adaptive_charging_controller.cc to
// make sure the interface works correctly with other values.
const int64_t kDefaultTestPercent = 70;

class FakeDelegate : public AdaptiveChargingControllerInterface::Delegate {
 public:
  bool SetBatterySustain(int lower, int upper) override {
    fake_lower = lower;
    fake_upper = upper;
    return true;
  }

  bool SetBatteryChargeLimit(uint32_t limit_mA) override {
    fake_limit = limit_mA;
    return true;
  }

  void GetAdaptiveChargingPrediction(const assist_ranker::RankerExample& proto,
                                     bool async) override {
    adaptive_charging_controller_->OnPredictionResponse(true, fake_result);
  }

  void GenerateAdaptiveChargingUnplugMetrics(
      const metrics::AdaptiveChargingState state,
      const base::TimeTicks& target_time,
      const base::TimeTicks& hold_start_time,
      const base::TimeTicks& hold_end_time,
      const base::TimeTicks& charge_finished_time,
      const base::TimeDelta& time_spent_slow_charging,
      double display_battery_percentage) override {
    adaptive_state = state;
  }

  AdaptiveChargingController* adaptive_charging_controller_;
  // The vector of doubles that represent the probability of unplug for each
  // associated hour, except for the last result, which is the probability of
  // unplug after the corresponding hour for the second to last result.
  std::vector<double> fake_result;
  int fake_lower;
  int fake_upper;
  uint32_t fake_limit;
  metrics::AdaptiveChargingState adaptive_state;
};

}  // namespace

class AdaptiveChargingControllerTest : public TestEnvironment {
 public:
  AdaptiveChargingControllerTest() {
    auto recheck_alarm = brillo::timers::SimpleAlarmTimer::CreateForTesting();
    auto charge_alarm = brillo::timers::SimpleAlarmTimer::CreateForTesting();
    recheck_alarm_ = recheck_alarm.get();
    charge_alarm_ = charge_alarm.get();
    delegate_.adaptive_charging_controller_ = &adaptive_charging_controller_;
    delegate_.fake_result = {0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0};
    delegate_.fake_lower = kBatterySustainDisabled;
    delegate_.fake_upper = kBatterySustainDisabled;
    delegate_.fake_limit = kSlowChargingDisabled;
    power_status_.external_power = PowerSupplyProperties_ExternalPower_AC;
    power_status_.display_battery_percentage = kDefaultTestPercent;
    power_status_.battery_state = PowerSupplyProperties_BatteryState_CHARGING;
    power_supply_.set_status(power_status_);
    adaptive_charging_controller_.set_recheck_alarm_for_testing(
        std::move(recheck_alarm));
    adaptive_charging_controller_.set_charge_alarm_for_testing(
        std::move(charge_alarm));
    platform_features_ =
        std::make_unique<feature::FakePlatformFeatures>(dbus_wrapper_.GetBus());
    prefs_.SetInt64(kAdaptiveChargingHoldPercentPref, kDefaultTestPercent);
    EXPECT_TRUE(temp_dir_.CreateUniqueTempDir());
    EXPECT_TRUE(temp_dir_.IsValid());
    charge_history_dir_ = temp_dir_.GetPath().Append("charge_history");
    charge_events_dir_ = charge_history_dir_.Append("charge_events");
    hold_time_on_ac_dir_ = charge_history_dir_.Append("hold_time_on_ac");
    time_full_on_ac_dir_ = charge_history_dir_.Append("time_full_on_ac");
    time_on_ac_dir_ = charge_history_dir_.Append("time_on_ac");
    charge_history_ =
        adaptive_charging_controller_.get_charge_history_for_testing();
    charge_history_->set_charge_history_dir_for_testing(charge_history_dir_);
  }

  ~AdaptiveChargingControllerTest() override = default;

  void CreateDefaultChargeHistory() {
    CreateChargeHistoryDirectories();
    // Tests may adjust the time to avoid race conditions around midnight, etc.,
    // so use that time if it was set.
    base::Time now = charge_history_->clock()->GetCurrentWallTime();
    base::Time today = now.UTCMidnight();
    for (int i = 0; i < 15; ++i) {
      WriteChargeHistoryFile(charge_events_dir_,
                             today - (i + 1) * base::Hours(20),
                             base::Hours(i + 1));
      WriteChargeHistoryFile(time_on_ac_dir_, today - i * base::Days(1),
                             base::Hours(5));
      WriteChargeHistoryFile(time_full_on_ac_dir_, today - i * base::Days(1),
                             base::Hours(2));
      WriteChargeHistoryFile(hold_time_on_ac_dir_, today - i * base::Days(1),
                             base::Hours(1));
    }
  }

  void SetHoldCharge() {
    power_status_.battery_percentage = 77;
    power_status_.display_battery_percentage = 80;
    power_status_.adaptive_delaying_charge = true;
    power_supply_.set_status(power_status_);
    power_status_.battery_state = PowerSupplyProperties_BatteryState_CHARGING;
    power_supply_.NotifyObservers();
  }

  void SetFullCharge() {
    power_status_.battery_percentage = 100;
    power_status_.display_battery_percentage = 100;
    power_status_.adaptive_delaying_charge = false;
    power_status_.battery_state = PowerSupplyProperties_BatteryState_FULL;
    power_supply_.set_status(power_status_);
    power_supply_.NotifyObservers();
  }

  void InitNoHistory() {
    adaptive_charging_controller_.Init(
        &delegate_, &backlight_controller_, &input_watcher_, &power_supply_,
        &dbus_wrapper_, platform_features_.get(), &prefs_);
    power_supply_.NotifyObservers();

    // Adaptive Charging is not enabled yet.
    EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
    EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);

    PowerManagementPolicy policy;
    policy.set_adaptive_charging_enabled(true);
    adaptive_charging_controller_.HandlePolicyChange(policy);
  }

  void Init() {
    CreateDefaultChargeHistory();
    InitNoHistory();
    EXPECT_TRUE(charge_alarm_->IsRunning());
    EXPECT_TRUE(recheck_alarm_->IsRunning());
    EXPECT_EQ(delegate_.fake_lower, kDefaultTestPercent);
    EXPECT_EQ(delegate_.fake_upper, kDefaultTestPercent);
  }

  void InitFullChargeNoHistory() {
    power_status_.battery_percentage = 100;
    power_status_.display_battery_percentage = 100;
    power_status_.adaptive_delaying_charge = false;
    power_status_.battery_state = PowerSupplyProperties_BatteryState_FULL;
    power_supply_.set_status(power_status_);
    adaptive_charging_controller_.Init(
        &delegate_, &backlight_controller_, &input_watcher_, &power_supply_,
        &dbus_wrapper_, platform_features_.get(), &prefs_);
    power_supply_.NotifyObservers();

    // Adaptive Charging is not enabled yet.
    EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
    EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);

    PowerManagementPolicy policy;
    policy.set_adaptive_charging_enabled(true);
    adaptive_charging_controller_.HandlePolicyChange(policy);

    // Adaptive Charging is not started when charge is full.
    EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
    EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);
  }

  void InitFullCharge() {
    CreateDefaultChargeHistory();
    InitFullChargeNoHistory();
  }

  void DisconnectCharger() {
    power_status_.external_power =
        PowerSupplyProperties_ExternalPower_DISCONNECTED;
    power_status_.battery_state =
        PowerSupplyProperties_BatteryState_DISCHARGING;
    power_supply_.set_status(power_status_);
    power_supply_.NotifyObservers();
  }

  void ConnectCharger() {
    // Leave whether to set `power_status_.battery_state` to FULL or CHARGING to
    // the caller.
    power_status_.external_power = PowerSupplyProperties_ExternalPower_AC;
    power_supply_.set_status(power_status_);
    power_supply_.NotifyObservers();
  }

  void CreateChargeHistoryDirectories() {
    EXPECT_FALSE(base::DirectoryExists(charge_history_dir_));
    EXPECT_TRUE(CreateDirectory(charge_history_dir_));
    EXPECT_TRUE(CreateDirectory(charge_events_dir_));
    EXPECT_TRUE(CreateDirectory(hold_time_on_ac_dir_));
    EXPECT_TRUE(CreateDirectory(time_full_on_ac_dir_));
    EXPECT_TRUE(CreateDirectory(time_on_ac_dir_));
  }

  base::Time FloorTime(base::Time time) {
    base::TimeDelta conv =
        time.ToDeltaSinceWindowsEpoch().FloorToMultiple(base::Minutes(15));
    return base::Time::FromDeltaSinceWindowsEpoch(conv);
  }

  void CreateChargeHistoryFile(const base::FilePath& dir,
                               const base::Time& start) {
    base::Value val = base::TimeToValue(FloorTime(start));
    std::optional<base::FilePath> opt_path = base::ValueToFilePath(val);
    base::File file(dir.Append(opt_path.value()),
                    base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_READ |
                        base::File::FLAG_WRITE);
    EXPECT_TRUE(file.IsValid());
  }

  int NumChargeHistoryFiles(const base::FilePath& dir) {
    base::FileEnumerator file_enum(dir, false, base::FileEnumerator::FILES);
    int num_files = 0;
    for (base::FilePath path = file_enum.Next(); !path.empty();
         path = file_enum.Next()) {
      num_files++;
    }
    return num_files;
  }

  void WriteChargeHistoryFile(const base::FilePath& dir,
                              const base::Time& start,
                              const base::TimeDelta& duration) {
    base::Value val = base::TimeToValue(FloorTime(start));
    std::optional<base::FilePath> opt_path = base::ValueToFilePath(val);
    JSONFileValueSerializer serializer(dir.Append(opt_path.value()));
    EXPECT_TRUE(serializer.Serialize(base::TimeDeltaToValue(duration)));
  }

  bool ChargeHistoryFileExists(const base::FilePath& dir,
                               const base::Time& start) {
    base::Value val = base::TimeToValue(FloorTime(start));
    std::optional<base::FilePath> opt_path = base::ValueToFilePath(val);
    return base::PathExists(dir.Append(opt_path.value()));
  }

  base::TimeDelta ReadTimeDeltaFromFile(const base::FilePath& path) {
    JSONFileValueDeserializer deserializer(path);
    int error;
    std::string error_msg;
    auto val_ptr = deserializer.Deserialize(&error, &error_msg);
    return base::ValueToTimeDelta(*val_ptr).value();
  }

  base::TimeDelta ReadChargeHistoryFile(const base::FilePath& dir,
                                        const base::Time& start) {
    base::Value val = base::TimeToValue(FloorTime(start));
    std::optional<base::FilePath> opt_path = base::ValueToFilePath(val);
    return ReadTimeDeltaFromFile(dir.Append(opt_path.value()));
  }

  // Converts unplug time prediction into fake_result vector.
  std::vector<double> ConvertUnplugTimeIntoPredictionBuckets(
      double hour_to_unplug) {
    std::vector<double> result(9, 0.0);
    result.at(static_cast<int>(hour_to_unplug)) = 1.0;
    return result;
  }

  // Simulate time passing with various predictions, and return how much time
  // we spend slow charging before adaptive charging is stopped. The
  // `predicted_times` vector contains the predicted time-until-unplug made by
  // the ML model every half an hour.
  base::TimeDelta ObtainPredictionOutcome(std::vector<double> predicted_times) {
    prefs_.SetBool(kSlowAdaptiveChargingEnabledPref, true);
    power_status_.battery_charge_full_design = 6.310;
    power_supply_.set_status(power_status_);
    Clock* clock = adaptive_charging_controller_.clock();
    Init();
    base::TimeDelta time_spent_slow_charging;

    for (double time : predicted_times) {
      // Update the fake_result vector to simulate a new prediction.
      delegate_.fake_result = ConvertUnplugTimeIntoPredictionBuckets(time);

      // Run the recheck alarm to obtain prediction response.
      adaptive_charging_controller_.set_recheck_delay_for_testing(
          base::TimeDelta());
      base::RunLoop().RunUntilIdle();

      // If slow adaptive charging has been stopped, return.
      if (delegate_.fake_limit == kSlowChargingDisabled) {
        break;
      }

      // Simulate time moving forward by 30 minutes.
      clock->set_current_boot_time_for_testing(clock->GetCurrentBootTime() +
                                               base::Minutes(30));

      // Determine if we are slow charging and update the amount of time spent
      // slow charging.
      if (delegate_.fake_limit == 631) {
        time_spent_slow_charging += base::Minutes(30);
      }
    }

    return time_spent_slow_charging;
  }

 protected:
  FakeDelegate delegate_;
  policy::BacklightControllerStub backlight_controller_;
  system::InputWatcherStub input_watcher_;
  system::PowerSupplyStub power_supply_;
  system::DBusWrapperStub dbus_wrapper_;
  FakePrefs prefs_;
  std::unique_ptr<feature::FakePlatformFeatures> platform_features_;
  brillo::timers::SimpleAlarmTimer* recheck_alarm_;
  brillo::timers::SimpleAlarmTimer* charge_alarm_;
  system::PowerStatus power_status_;
  base::ScopedTempDir temp_dir_;
  base::FilePath charge_history_dir_;
  base::FilePath charge_events_dir_;
  base::FilePath hold_time_on_ac_dir_;
  base::FilePath time_full_on_ac_dir_;
  base::FilePath time_on_ac_dir_;
  AdaptiveChargingController adaptive_charging_controller_;
  ChargeHistory* charge_history_;
};

// Test that the alarms are properly set when Adaptive Charging starts, when the
// power_status is updated, and when suspend occurs.
TEST_F(AdaptiveChargingControllerTest, TestAlarmSet) {
  // Set the display_battery_percentage to be less than the hold percent, so
  // that the target full charge time can increase.
  power_status_.display_battery_percentage = kDefaultTestPercent - 10.0;
  power_supply_.set_status(power_status_);
  delegate_.fake_result = {0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0};
  Init();

  // Record the initial charge delay with the `fake_result` as defined above.
  base::TimeDelta start_delta =
      adaptive_charging_controller_.get_charge_delay_for_testing();

  // This will trigger the `AdaptiveChargingController::recheck_alarm_`, which
  // will set a new charge delay.
  delegate_.fake_result[3] = 0.0;
  delegate_.fake_result[5] = 1.0;
  adaptive_charging_controller_.set_recheck_delay_for_testing(
      base::TimeDelta());
  base::RunLoop().RunUntilIdle();
  base::TimeDelta recheck_delta =
      adaptive_charging_controller_.get_charge_delay_for_testing();

  // We extended the prediction for when the system would unplug by two hours,
  // but just check for > 1 hour due to timestamps being slightly off.
  EXPECT_GT(recheck_delta - start_delta, base::Hours(1));

  // This will set yet another charge delay, as triggered by a suspend attempt.
  delegate_.fake_result[5] = 0.0;
  delegate_.fake_result[7] = 1.0;
  adaptive_charging_controller_.PrepareForSuspendAttempt();
  base::TimeDelta suspend_delta =
      adaptive_charging_controller_.get_charge_delay_for_testing();
  EXPECT_GT(suspend_delta - recheck_delta, base::Hours(1));
}

// Test that the command to the EC to clear the battery sustain status is sent
// when AdaptiveChargingController should disable it.
TEST_F(AdaptiveChargingControllerTest, TestBatterySustainClearedDisconnect) {
  Init();
  // When external power is unplugged.
  DisconnectCharger();
  EXPECT_FALSE(recheck_alarm_->IsRunning());
  EXPECT_FALSE(charge_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);
}

// Test that a change in prediction to the system unplugged soon will result in
// Adaptive Charging being stopped.
TEST_F(AdaptiveChargingControllerTest, TestNoDelayOnPrediction) {
  Init();
  delegate_.fake_result = {1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0};
  adaptive_charging_controller_.set_recheck_delay_for_testing(
      base::TimeDelta());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(recheck_alarm_->IsRunning());
  EXPECT_FALSE(charge_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);
}

// Test that disabling Adaptive Charging via DBus works correctly.
TEST_F(AdaptiveChargingControllerTest, TestDBusEnableDisable) {
  PowerManagementPolicy policy;
  Init();
  policy.set_adaptive_charging_enabled(false);
  adaptive_charging_controller_.HandlePolicyChange(policy);

  // We still run the recheck and charge alarm to report metrics.
  EXPECT_TRUE(recheck_alarm_->IsRunning());
  EXPECT_TRUE(charge_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);
}

// Test that the charge alarm will enable charging when it goes off.
TEST_F(AdaptiveChargingControllerTest, TestChargeAlarm) {
  Init();
  adaptive_charging_controller_.set_charge_delay_for_testing(base::TimeDelta());
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(recheck_alarm_->IsRunning());
  EXPECT_FALSE(charge_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);
}

TEST_F(AdaptiveChargingControllerTest, TestStoppedOnShutdown) {
  Init();
  adaptive_charging_controller_.HandleShutdown();

  EXPECT_FALSE(recheck_alarm_->IsRunning());
  EXPECT_FALSE(charge_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);

  // Check that a policy update doesn't start Adaptive Charging
  PowerManagementPolicy policy;
  policy.set_adaptive_charging_enabled(true);
  adaptive_charging_controller_.HandlePolicyChange(policy);

  EXPECT_FALSE(recheck_alarm_->IsRunning());
  EXPECT_FALSE(charge_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);
}

// Test that the sustain settings are set based on
// `PowerStatus.display_battery_percentage` when it's higher than
// `hold_percent_`.
TEST_F(AdaptiveChargingControllerTest, TestAdjustedSustain) {
  Init();

  PowerManagementPolicy policy;
  policy.set_adaptive_charging_hold_percent(kDefaultTestPercent - 10);
  adaptive_charging_controller_.HandlePolicyChange(policy);

  EXPECT_TRUE(charge_alarm_->IsRunning());
  EXPECT_TRUE(recheck_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_lower, kDefaultTestPercent);
  EXPECT_EQ(delegate_.fake_upper, kDefaultTestPercent);
}

// Test that we set an infinite charge delay when the charger is expected to be
// unplugged > 8 hours from now.
TEST_F(AdaptiveChargingControllerTest, TestMaxTimeSustain) {
  Init();

  delegate_.fake_result = {0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0};
  PowerManagementPolicy policy;
  // Set the percentile for the max delay heuristic to 1.0, which effectively
  // disables the heuristic.
  policy.set_adaptive_charging_max_delay_percentile(1.0);
  // Disable then enable Adaptive Charging to allow the charge delay to go up,
  // since we will already have a target charge time from calling Init and we
  // reached the hold percent (which prevents the charge delay from increasing).
  policy.set_adaptive_charging_enabled(false);
  adaptive_charging_controller_.HandlePolicyChange(policy);
  policy.set_adaptive_charging_enabled(true);
  adaptive_charging_controller_.HandlePolicyChange(policy);

  // The TimeTicks value is a max int, not an infinite value.
  EXPECT_FALSE(charge_alarm_->IsRunning());
  EXPECT_EQ(
      base::TimeTicks::Max(),
      adaptive_charging_controller_.get_target_full_charge_time_for_testing());
  EXPECT_EQ(delegate_.fake_lower, kDefaultTestPercent);
  EXPECT_EQ(delegate_.fake_upper, kDefaultTestPercent);
}

// Test that the prediction for Adaptive Charging is based on the iterative sum
// of the result.
TEST_F(AdaptiveChargingControllerTest, TestProbabilitySum) {
  Clock* clock = adaptive_charging_controller_.clock();
  clock->set_current_boot_time_for_testing(base::TimeTicks() +
                                           base::Seconds(1));
  Init();

  delegate_.fake_result = {0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.2};
  PowerManagementPolicy policy;
  // Adjust the `max_delay_percentile` to make sure our predictions aren't
  // limited by it.
  policy.set_adaptive_charging_max_delay_percentile(1.0);
  policy.set_adaptive_charging_min_probability(0.5);
  adaptive_charging_controller_.HandlePolicyChange(policy);
  EXPECT_TRUE(charge_alarm_->IsRunning());
  EXPECT_EQ(
      clock->GetCurrentBootTime() + base::Hours(4),
      adaptive_charging_controller_.get_target_full_charge_time_for_testing());

  // Check that changing the |min_probability| restarts Adaptive Charging as
  // well.
  policy.set_adaptive_charging_min_probability(0.6);
  adaptive_charging_controller_.HandlePolicyChange(policy);
  EXPECT_TRUE(charge_alarm_->IsRunning());
  EXPECT_EQ(
      clock->GetCurrentBootTime() + base::Hours(5),
      adaptive_charging_controller_.get_target_full_charge_time_for_testing());

  policy.set_adaptive_charging_min_probability(0.9);
  adaptive_charging_controller_.HandlePolicyChange(policy);
  EXPECT_FALSE(charge_alarm_->IsRunning());
  EXPECT_EQ(
      base::TimeTicks::Max(),
      adaptive_charging_controller_.get_target_full_charge_time_for_testing());
}

// Test that calling the ChargeNowForAdaptiveCharging method via dbus
// successfully stops Adaptive Charging.
TEST_F(AdaptiveChargingControllerTest, TestChargeNow) {
  Init();

  // Call the ChargeNow DBus method, then check that Adaptive Charging is
  // disabled.
  dbus::MethodCall method_call(kPowerManagerInterface,
                               kChargeNowForAdaptiveChargingMethod);
  std::unique_ptr<dbus::Response> response =
      dbus_wrapper_.CallExportedMethodSync(&method_call);
  EXPECT_TRUE(response &&
              response->GetMessageType() != dbus::Message::MESSAGE_ERROR);
  EXPECT_FALSE(recheck_alarm_->IsRunning());
  EXPECT_FALSE(charge_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);

  // Check that Adaptive Charging successfully starts again after unplugging
  // then plugging the AC charger.
  DisconnectCharger();
  power_status_.battery_state = PowerSupplyProperties_BatteryState_CHARGING;
  ConnectCharger();
  EXPECT_TRUE(charge_alarm_->IsRunning());
  EXPECT_TRUE(recheck_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_lower, kDefaultTestPercent);
  EXPECT_EQ(delegate_.fake_upper, kDefaultTestPercent);
}

// Test that the GetChargeHistory DBus method accurately returns the Charge
// History.
TEST_F(AdaptiveChargingControllerTest, TestGetChargeHistory) {
  // Set wall time to avoid race conditions with midnight creating another day
  // for Charge History.
  base::Time now = base::Time::Now().UTCMidnight();
  charge_history_->clock()->set_current_wall_time_for_testing(now);
  Init();

  ChargeHistoryState proto;
  dbus::MethodCall method_call(kPowerManagerInterface, kGetChargeHistoryMethod);
  std::unique_ptr<dbus::Response> response =
      dbus_wrapper_.CallExportedMethodSync(&method_call);
  EXPECT_TRUE(response &&
              response->GetMessageType() != dbus::Message::MESSAGE_ERROR);
  proto.Clear();
  EXPECT_TRUE(
      dbus::MessageReader(response.get()).PopArrayOfBytesAsProto(&proto));

  std::vector<std::pair<int64_t, int64_t>> stored_charge_events;
  // We write 15 charge events when creating history, plus there's the
  // incomplete charge event, since we're plugged in.
  EXPECT_EQ(proto.charge_event().size(), 16);
  for (auto& event : proto.charge_event()) {
    stored_charge_events.emplace_back(event.start_time(), event.duration());
  }

  // Reverse sort these values, so that we can verify the values in the
  // same order they were generated in CreateDefaultChargeHistory.
  std::sort(stored_charge_events.begin(), stored_charge_events.end(),
            std::greater<>());

  // The incomplete charge event that isn't created in
  // CreateDefaultChargeHistory will be at the front, so skip it. This also
  // means that the "i + 1" for charge events created in that function are
  // changed to just "i".
  for (size_t i = 1; i < proto.charge_event().size(); i++) {
    EXPECT_EQ(base::Time::FromDeltaSinceWindowsEpoch(
                  base::Microseconds(stored_charge_events[i].first)),
              now - i * base::Hours(20));
    EXPECT_EQ(base::Microseconds(stored_charge_events[i].second),
              base::Hours(i));
  }

  // Check the start time and duration of the incomplete charge event.
  EXPECT_EQ(base::Time::FromDeltaSinceWindowsEpoch(
                base::Microseconds(stored_charge_events[0].first)),
            now);
  EXPECT_EQ(base::Microseconds(stored_charge_events[0].second),
            base::TimeDelta());

  std::vector<int64_t> stored_midnights;
  EXPECT_EQ(proto.daily_history().size(), 15);
  for (auto& history : proto.daily_history()) {
    stored_midnights.push_back(history.utc_midnight());
    EXPECT_EQ(base::Microseconds(history.time_on_ac()), base::Hours(5));
    EXPECT_EQ(base::Microseconds(history.time_full_on_ac()), base::Hours(2));
    EXPECT_EQ(base::Microseconds(history.hold_time_on_ac()), base::Hours(1));
  }

  std::sort(stored_midnights.begin(), stored_midnights.end());
  for (size_t i = 0; i < stored_midnights.size(); i++) {
    EXPECT_EQ(base::Time::FromDeltaSinceWindowsEpoch(
                  base::Microseconds(stored_midnights[i])),
              now - base::Days(stored_midnights.size() - i - 1));
  }
}

// Test that we don't start Adaptive Charging when the battery is already full.
TEST_F(AdaptiveChargingControllerTest, TestFullCharge) {
  // This verifies that Adaptive Charging doesn't start when enabled via policy.
  InitFullCharge();

  // Verify that Adaptive Charging doesn't start on unplug/plug as well.
  DisconnectCharger();
  power_status_.battery_state = PowerSupplyProperties_BatteryState_FULL;
  ConnectCharger();
  EXPECT_FALSE(recheck_alarm_->IsRunning());
  EXPECT_FALSE(charge_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);
}

// Test that no Adaptive Charging alarm is running on a suspend attempt when the
// charger is disconnected.
TEST_F(AdaptiveChargingControllerTest, TestNoAlarmOnBattery) {
  Init();
  DisconnectCharger();
  adaptive_charging_controller_.PrepareForSuspendAttempt();

  EXPECT_FALSE(recheck_alarm_->IsRunning());
  EXPECT_FALSE(charge_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);
}

// Test that sub-directories are created, permissions are modified, and initial
// files are created when the base Charge History directory doesn't even exist.
TEST_F(AdaptiveChargingControllerTest, TestEmptyChargeHistory) {
  // Init will cause power_supply_ to notify observers, which will init Charge
  // History.
  InitNoHistory();

  // Check that directories are created.
  EXPECT_TRUE(base::DirectoryExists(charge_history_dir_));
  EXPECT_TRUE(base::DirectoryExists(charge_events_dir_));
  EXPECT_TRUE(base::DirectoryExists(hold_time_on_ac_dir_));
  EXPECT_TRUE(base::DirectoryExists(time_full_on_ac_dir_));
  EXPECT_TRUE(base::DirectoryExists(time_on_ac_dir_));

  // Verify permissions of directories are such that only powerd and root can
  // read/write charge history.
  int mode;
  EXPECT_TRUE(base::GetPosixFilePermissions(charge_history_dir_, &mode));
  EXPECT_EQ(0700, mode);
  EXPECT_TRUE(base::GetPosixFilePermissions(charge_events_dir_, &mode));
  EXPECT_EQ(0700, mode);
  EXPECT_TRUE(base::GetPosixFilePermissions(hold_time_on_ac_dir_, &mode));
  EXPECT_EQ(0700, mode);
  EXPECT_TRUE(base::GetPosixFilePermissions(time_full_on_ac_dir_, &mode));
  EXPECT_EQ(0700, mode);
  EXPECT_TRUE(base::GetPosixFilePermissions(time_on_ac_dir_, &mode));
  EXPECT_EQ(0700, mode);

  // Check that there is one empty file in `charge_events_dir_`, which indicates
  // the charger was plugged in, and hasn't been unplugged yet.
  base::FileEnumerator events_dir(charge_events_dir_, false,
                                  base::FileEnumerator::FILES);
  for (base::FilePath path = events_dir.Next(); !path.empty();
       path = events_dir.Next()) {
    // charge event should not have a duration yet.
    EXPECT_EQ(0, events_dir.GetInfo().GetSize());
  }
  EXPECT_EQ(1, NumChargeHistoryFiles(charge_events_dir_));

  // Check that the current day is created for the `hold_time_on_ac_dir_`,
  // `time_full_on_ac_dir_` and `time_on_ac_dir_`.
  base::FileEnumerator hold_on_ac_dir(hold_time_on_ac_dir_, false,
                                      base::FileEnumerator::FILES);
  for (base::FilePath path = hold_on_ac_dir.Next(); !path.empty();
       path = hold_on_ac_dir.Next()) {
    EXPECT_EQ(base::TimeDelta(), ReadTimeDeltaFromFile(path));
  }
  EXPECT_EQ(1, NumChargeHistoryFiles(hold_time_on_ac_dir_));

  base::FileEnumerator full_on_ac_dir(time_full_on_ac_dir_, false,
                                      base::FileEnumerator::FILES);
  for (base::FilePath path = full_on_ac_dir.Next(); !path.empty();
       path = full_on_ac_dir.Next()) {
    EXPECT_EQ(base::TimeDelta(), ReadTimeDeltaFromFile(path));
  }
  EXPECT_EQ(1, NumChargeHistoryFiles(time_full_on_ac_dir_));

  base::FileEnumerator on_ac_dir(time_on_ac_dir_, false,
                                 base::FileEnumerator::FILES);
  for (base::FilePath path = on_ac_dir.Next(); !path.empty();
       path = on_ac_dir.Next()) {
    EXPECT_EQ(base::TimeDelta(), ReadTimeDeltaFromFile(path));
  }
  EXPECT_EQ(1, NumChargeHistoryFiles(time_on_ac_dir_));
}

// Verify that timestamps are 15 minute aligned for privacy reasons.
TEST_F(AdaptiveChargingControllerTest, TestTimeAlignment) {
  // Set time to 5 minutes before midnight so that it isn't a multiple of
  // `kChargeHistoryTimeInterval`, and thus the duration will be floored.
  base::Time now = base::Time::Now().UTCMidnight() - base::Minutes(5);
  charge_history_->clock()->set_current_wall_time_for_testing(now);
  // Make an initial charge event about 40 minutes ago (not unplugged yet).
  base::Time event_time = FloorTime(now - base::Minutes(40));
  CreateChargeHistoryDirectories();
  CreateChargeHistoryFile(charge_events_dir_, event_time);
  InitNoHistory();

  // Disconnect power, which should cause Charge History to be written.
  DisconnectCharger();

  base::TimeDelta duration =
      ReadChargeHistoryFile(charge_events_dir_, event_time);
  EXPECT_EQ(base::Minutes(30), duration);
  EXPECT_EQ(base::Minutes(30), charge_history_->GetTimeOnAC());

  // Battery was never full.
  EXPECT_EQ(base::TimeDelta(), charge_history_->GetTimeFullOnAC());
}

// Test that all of the file updates that need to happen on unplug occur.
TEST_F(AdaptiveChargingControllerTest, HistoryWrittenOnUnplug) {
  // Set time to exactly midnight to avoid rounding issues with
  // timestamps getting floored to multiples of `kChargeHistoryTimeInterval`.
  base::Time now = base::Time::Now().UTCMidnight();
  base::Time event_time = FloorTime(now - base::Days(3));
  charge_history_->clock()->set_current_wall_time_for_testing(now);
  CreateChargeHistoryDirectories();
  CreateChargeHistoryFile(charge_events_dir_, event_time);
  InitNoHistory();
  DisconnectCharger();

  EXPECT_EQ(base::Days(3),
            ReadChargeHistoryFile(charge_events_dir_, event_time));
}

// Test that we record pending time to `time_full_on_ac_dir_` and
// `hold_time_on_ac_dir_`  when entering suspend and shutdown.
TEST_F(AdaptiveChargingControllerTest, TimeFullWrittenOnLowPowerStates) {
  base::Time now = base::Time::Now().UTCMidnight();
  base::TimeTicks ticks = base::TimeTicks::Now();
  Clock* clock = charge_history_->clock();
  clock->set_current_wall_time_for_testing(now - base::Hours(2));
  clock->set_current_boot_time_for_testing(ticks - base::Hours(2));
  CreateChargeHistoryDirectories();
  CreateChargeHistoryFile(charge_events_dir_, now - base::Hours(3));
  InitNoHistory();

  SetHoldCharge();
  clock->set_current_wall_time_for_testing(now - base::Hours(1));
  clock->set_current_boot_time_for_testing(ticks - base::Hours(1));

  SetFullCharge();
  clock->set_current_wall_time_for_testing(now);
  clock->set_current_boot_time_for_testing(ticks);

  adaptive_charging_controller_.PrepareForSuspendAttempt();
  base::TimeDelta duration = base::TimeDelta();
  base::FileEnumerator full_on_ac_dir(time_full_on_ac_dir_, false,
                                      base::FileEnumerator::FILES);
  for (base::FilePath path = full_on_ac_dir.Next(); !path.empty();
       path = full_on_ac_dir.Next())
    duration += ReadTimeDeltaFromFile(path);

  EXPECT_EQ(base::Hours(1), duration);

  base::FileEnumerator hold_on_ac_dir(hold_time_on_ac_dir_, false,
                                      base::FileEnumerator::FILES);
  duration = base::TimeDelta();
  for (base::FilePath path = hold_on_ac_dir.Next(); !path.empty();
       path = hold_on_ac_dir.Next())
    duration += ReadTimeDeltaFromFile(path);

  EXPECT_EQ(base::Hours(1), duration);
}

// Test that our retention policy is properly enforced on Init.
TEST_F(AdaptiveChargingControllerTest, HistoryRetentionOnInit) {
  // The first two events should be kept, since we delete events that are 30+
  // days old from the time of unplug (not plug in).
  base::Time now = base::Time::Now();
  std::vector<base::Time> event_times = {
      now - base::Days(7), now - base::Days(31), now - base::Days(32)};
  std::vector<base::TimeDelta> event_durations = {base::Hours(2), base::Days(2),
                                                  base::Hours(10)};
  CreateChargeHistoryDirectories();
  for (int i = 0; i < event_times.size(); i++) {
    WriteChargeHistoryFile(charge_events_dir_, FloorTime(event_times[i]),
                           event_durations[i]);
    WriteChargeHistoryFile(hold_time_on_ac_dir_, event_times[i].UTCMidnight(),
                           base::Hours(1));
    WriteChargeHistoryFile(time_full_on_ac_dir_, event_times[i].UTCMidnight(),
                           event_durations[i] - base::Hours(2));
    WriteChargeHistoryFile(time_on_ac_dir_, event_times[i].UTCMidnight(),
                           event_durations[i]);
  }

  // Add in some days with no charging.
  for (base::Time date = now.UTCMidnight(); date > now - base::Days(5);
       date -= base::Days(1)) {
    WriteChargeHistoryFile(hold_time_on_ac_dir_, date, base::TimeDelta());
    WriteChargeHistoryFile(time_full_on_ac_dir_, date, base::TimeDelta());
    WriteChargeHistoryFile(time_on_ac_dir_, date, base::TimeDelta());
  }

  InitNoHistory();
  EXPECT_EQ(event_durations[0],
            ReadChargeHistoryFile(charge_events_dir_, event_times[0]));
  EXPECT_EQ(event_durations[1],
            ReadChargeHistoryFile(charge_events_dir_, event_times[1]));
  EXPECT_FALSE(ChargeHistoryFileExists(charge_events_dir_, event_times[2]));

  // 2 of the existing files, and the empty charge event created on Init since
  // the charger is connected.
  EXPECT_EQ(3, NumChargeHistoryFiles(charge_events_dir_));
  EXPECT_TRUE(ChargeHistoryFileExists(time_full_on_ac_dir_,
                                      event_times[0].UTCMidnight()));
  EXPECT_FALSE(ChargeHistoryFileExists(time_full_on_ac_dir_,
                                       event_times[1].UTCMidnight()));
  EXPECT_FALSE(ChargeHistoryFileExists(time_full_on_ac_dir_,
                                       event_times[2].UTCMidnight()));
  EXPECT_TRUE(ChargeHistoryFileExists(hold_time_on_ac_dir_,
                                      event_times[0].UTCMidnight()));
  EXPECT_FALSE(ChargeHistoryFileExists(hold_time_on_ac_dir_,
                                       event_times[1].UTCMidnight()));
  EXPECT_FALSE(ChargeHistoryFileExists(hold_time_on_ac_dir_,
                                       event_times[2].UTCMidnight()));
  EXPECT_TRUE(
      ChargeHistoryFileExists(time_on_ac_dir_, event_times[0].UTCMidnight()));
  EXPECT_FALSE(
      ChargeHistoryFileExists(time_on_ac_dir_, event_times[1].UTCMidnight()));
  EXPECT_FALSE(
      ChargeHistoryFileExists(time_on_ac_dir_, event_times[2].UTCMidnight()));
  for (base::Time date = now.UTCMidnight(); date > now - base::Days(5);
       date -= base::Days(1)) {
    EXPECT_TRUE(ChargeHistoryFileExists(hold_time_on_ac_dir_, date));
    EXPECT_TRUE(ChargeHistoryFileExists(time_full_on_ac_dir_, date));
    EXPECT_TRUE(ChargeHistoryFileExists(time_on_ac_dir_, date));
  }

  EXPECT_EQ(6, NumChargeHistoryFiles(hold_time_on_ac_dir_));
  EXPECT_EQ(6, NumChargeHistoryFiles(time_full_on_ac_dir_));
  EXPECT_EQ(6, NumChargeHistoryFiles(time_on_ac_dir_));
}

// Test that we limit the number of charge events to 50 on Init and when a new
// charge event is created.
TEST_F(AdaptiveChargingControllerTest, MaxChargeEvents) {
  CreateChargeHistoryDirectories();
  base::Time file_time = base::Time::Now() - base::Days(5);
  for (int i = 0; i < 100; i++) {
    WriteChargeHistoryFile(charge_events_dir_,
                           file_time + i * base::Minutes(30),
                           base::Minutes(15));
  }

  EXPECT_EQ(100, NumChargeHistoryFiles(charge_events_dir_));
  InitNoHistory();
  EXPECT_EQ(50, NumChargeHistoryFiles(charge_events_dir_));

  // Check that the correct charge event files still exist.
  for (int i = 51; i < 100; i++) {
    EXPECT_TRUE(ChargeHistoryFileExists(charge_events_dir_,
                                        file_time + i * base::Minutes(30)));
  }

  // Check that there are still 50 charge events after the latest charge event
  // has a duration written to it.
  DisconnectCharger();

  EXPECT_EQ(50, NumChargeHistoryFiles(charge_events_dir_));
}

// Test that the DaysOfHistory function works correctly.
TEST_F(AdaptiveChargingControllerTest, TestDaysOfHistory) {
  CreateChargeHistoryDirectories();
  base::Time now = base::Time::Now();
  base::Time today = now.UTCMidnight();
  for (int i = 0; i < 15; ++i) {
    WriteChargeHistoryFile(time_on_ac_dir_, today - (i + 5) * base::Days(1),
                           base::Hours(5));
    WriteChargeHistoryFile(time_full_on_ac_dir_,
                           today - (i + 5) * base::Days(1), base::Hours(2));
    WriteChargeHistoryFile(hold_time_on_ac_dir_,
                           today - (i + 5) * base::Days(1), base::Hours(2));
  }

  InitNoHistory();
  // ChargeHistory should append additional days between the last "time_on_ac"
  // day and now.
  EXPECT_EQ(20, charge_history_->DaysOfHistory());
}

// Test that the GetTime... functions works correctly.
TEST_F(AdaptiveChargingControllerTest, TestGetTimeFunctions) {
  base::Time now = base::Time::Now().UTCMidnight();
  Clock* clock = charge_history_->clock();
  clock->set_current_wall_time_for_testing(now);
  clock->set_current_boot_time_for_testing(base::TimeTicks::Now());
  CreateChargeHistoryDirectories();
  for (int i = 0; i < 15; ++i) {
    WriteChargeHistoryFile(time_on_ac_dir_, now - (i + 5) * base::Days(1),
                           base::Hours(5));
    WriteChargeHistoryFile(time_full_on_ac_dir_, now - (i + 5) * base::Days(1),
                           base::Hours(2));
    WriteChargeHistoryFile(hold_time_on_ac_dir_, now - (i + 5) * base::Days(1),
                           base::Hours(1));
  }

  CreateChargeHistoryFile(charge_events_dir_, now - base::Hours(10));

  InitNoHistory();
  base::TimeDelta time_on_ac = 15 * base::Hours(5) + base::Hours(10);
  base::TimeDelta time_full_on_ac = 15 * base::Hours(2);
  base::TimeDelta hold_time_on_ac = 15 * base::Hours(1);
  EXPECT_EQ(time_on_ac, charge_history_->GetTimeOnAC());
  EXPECT_EQ(time_full_on_ac, charge_history_->GetTimeFullOnAC());
  EXPECT_EQ(hold_time_on_ac, charge_history_->GetHoldTimeOnAC());

  // Set that we're holding charge, so that GetHoldTimeOnAC() will increase.
  SetHoldCharge();

  // Advance boot time and check that GetTime... values reflect that.
  clock->advance_current_boot_time_for_testing(base::Hours(1));
  clock->set_current_wall_time_for_testing(now + base::Hours(1));
  time_on_ac += base::Hours(1);
  hold_time_on_ac += base::Hours(1);
  EXPECT_EQ(time_on_ac, charge_history_->GetTimeOnAC());
  EXPECT_EQ(time_full_on_ac, charge_history_->GetTimeFullOnAC());
  EXPECT_EQ(hold_time_on_ac, charge_history_->GetHoldTimeOnAC());

  // Set charge to full, so that GetTimeFullOnAC() will also increase now.
  SetFullCharge();

  // Advance boot time and check that GetTime... values reflect that.
  clock->advance_current_boot_time_for_testing(base::Hours(1));
  clock->set_current_wall_time_for_testing(now + base::Hours(1));
  time_on_ac += base::Hours(1);
  time_full_on_ac += base::Hours(1);
  EXPECT_EQ(time_on_ac, charge_history_->GetTimeOnAC());
  EXPECT_EQ(time_full_on_ac, charge_history_->GetTimeFullOnAC());
  EXPECT_EQ(hold_time_on_ac, charge_history_->GetHoldTimeOnAC());

  // Check that disconnecting power (and thus finalizing charge history numbers
  // based on the current charge event) doesn't change the GetTime... values.
  DisconnectCharger();

  EXPECT_EQ(time_on_ac, charge_history_->GetTimeOnAC());
  EXPECT_EQ(time_full_on_ac, charge_history_->GetTimeFullOnAC());
  EXPECT_EQ(hold_time_on_ac, charge_history_->GetHoldTimeOnAC());
}

// Test that only a few charge history days will result in Adaptive Charging
// being disabled by its heuristic.
TEST_F(AdaptiveChargingControllerTest, TestHeuristicDisabledOnDays) {
  CreateChargeHistoryDirectories();
  base::Time now = base::Time::Now();
  base::Time today = now.UTCMidnight();
  for (int i = 0; i < 5; ++i) {
    WriteChargeHistoryFile(time_on_ac_dir_, today - i * base::Days(1),
                           base::Hours(5));
    WriteChargeHistoryFile(time_full_on_ac_dir_, today - i * base::Days(1),
                           base::Hours(3));
    WriteChargeHistoryFile(hold_time_on_ac_dir_, today - i * base::Days(1),
                           base::Hours(1));
  }

  InitNoHistory();
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);
  DisconnectCharger();
  EXPECT_EQ(metrics::AdaptiveChargingState::HEURISTIC_DISABLED,
            delegate_.adaptive_state);
}

// Test that a sufficient number of days (min 14) tracked in ChargeHistory with
// a too low TimeFullOnAC / TimeOnAC ratio still results in Adaptive Charging
// being disabled by its heuristic.
TEST_F(AdaptiveChargingControllerTest, TestHeuristicDisabledOnRatio) {
  CreateChargeHistoryDirectories();
  base::Time now = base::Time::Now();
  base::Time today = now.UTCMidnight();
  for (int i = 0; i < 15; ++i) {
    WriteChargeHistoryFile(time_on_ac_dir_, today - i * base::Days(1),
                           base::Hours(5));
    WriteChargeHistoryFile(time_full_on_ac_dir_, today - i * base::Days(1),
                           base::Hours(1));
    WriteChargeHistoryFile(hold_time_on_ac_dir_, today - i * base::Days(1),
                           base::Hours(1));
  }

  InitNoHistory();
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);
  DisconnectCharger();
  EXPECT_EQ(metrics::AdaptiveChargingState::HEURISTIC_DISABLED,
            delegate_.adaptive_state);
}

// Test that a large time jump while ChargeHistory is keeping track of time will
// be accounted for. We expect that the plug in time and durations will be
// correct. This means if wall time jumps X days ahead (due to the RTC losing
// state for instance) while boot time doesn't, ChargeHistory will not add X
// days to any of its durations.
TEST_F(AdaptiveChargingControllerTest, TestSystemTimeJumpNoHistory) {
  Clock* clock = charge_history_->clock();
  base::Time now = base::Time::Now().UTCMidnight();
  base::Time old_now = now - base::Days(3);
  base::Time older_now = old_now - base::Days(2);
  clock->set_current_wall_time_for_testing(older_now);

  // ChargeHistory should initially create a file in `charge_events_dir_` with
  // `older_now` as the start time for charging, but change it to `old_now`
  // later on, after time changed to 2 days later.
  InitNoHistory();
  EXPECT_TRUE(ChargeHistoryFileExists(charge_events_dir_, older_now));

  // Check that hold_time_on_ac values aren't incremented.
  SetHoldCharge();
  clock->set_current_wall_time_for_testing(old_now);
  EXPECT_EQ(base::TimeDelta(), charge_history_->GetHoldTimeOnAC());

  // Check that time_full_on_ac values aren't incremented after changing the
  // wall time to `now`, which is 3 days later, without increasing boot time.
  SetFullCharge();
  clock->set_current_wall_time_for_testing(now);
  EXPECT_EQ(base::TimeDelta(), charge_history_->GetTimeFullOnAC());

  DisconnectCharger();
  EXPECT_FALSE(ChargeHistoryFileExists(charge_events_dir_, older_now));
  EXPECT_FALSE(ChargeHistoryFileExists(charge_events_dir_, old_now));
  EXPECT_TRUE(ChargeHistoryFileExists(charge_events_dir_, now));

  // Expect a zero duration charge event, zero time on AC, and zero time full on
  // AC.
  EXPECT_EQ(base::TimeDelta(), ReadChargeHistoryFile(charge_events_dir_, now));
  EXPECT_EQ(base::TimeDelta(),
            ReadChargeHistoryFile(time_full_on_ac_dir_, now));
  EXPECT_EQ(base::TimeDelta(),
            ReadChargeHistoryFile(hold_time_on_ac_dir_, now));
  EXPECT_EQ(base::TimeDelta(), ReadChargeHistoryFile(time_on_ac_dir_, now));
}

// Test that a time change with a preexisting plug in time (but no duration) is
// corrected when there's a time change. We do this because we expect large time
// changes to come from the RTC losing state, which likely occurred from
// draining the battery completely. This means that the preexisting plug in time
// likely came from after the RTC lost its state, since the RTC shouldn't lose
// its state when the system has power.
TEST_F(AdaptiveChargingControllerTest, TestSystemTimeJumpExistingChargeEvent) {
  CreateChargeHistoryDirectories();
  Clock* clock = charge_history_->clock();
  base::Time now = base::Time::Now().UTCMidnight();
  base::Time old_now = now - base::Days(5);
  base::Time yesterday = now - base::Days(1);
  base::Time event_time = now - base::Days(1);
  base::Time old_event_time = old_now - base::Days(1);
  clock->set_current_wall_time_for_testing(old_now);
  CreateChargeHistoryFile(charge_events_dir_, old_event_time);

  InitFullChargeNoHistory();
  EXPECT_TRUE(ChargeHistoryFileExists(charge_events_dir_, old_event_time));
  clock->set_current_wall_time_for_testing(now);
  DisconnectCharger();

  // The correct duration of the charge event is one day, since `old_event_time`
  // is 1 day before `old_now`.
  EXPECT_FALSE(ChargeHistoryFileExists(charge_events_dir_, old_event_time));
  EXPECT_EQ(1, NumChargeHistoryFiles(charge_events_dir_));
  EXPECT_TRUE(ChargeHistoryFileExists(charge_events_dir_, event_time));
  EXPECT_TRUE(ChargeHistoryFileExists(hold_time_on_ac_dir_, yesterday));
  EXPECT_TRUE(ChargeHistoryFileExists(time_full_on_ac_dir_, yesterday));
  EXPECT_TRUE(ChargeHistoryFileExists(time_on_ac_dir_, yesterday));

  EXPECT_EQ(base::Days(1),
            ReadChargeHistoryFile(charge_events_dir_, event_time));
  EXPECT_EQ(base::TimeDelta(),
            ReadChargeHistoryFile(hold_time_on_ac_dir_, yesterday));
  EXPECT_EQ(base::Days(1),
            ReadChargeHistoryFile(time_full_on_ac_dir_, yesterday));
  EXPECT_EQ(base::Days(1), ReadChargeHistoryFile(time_on_ac_dir_, yesterday));
}

TEST_F(AdaptiveChargingControllerTest, TestFutureChargeEventDeleted) {
  CreateChargeHistoryDirectories();
  base::Time now = base::Time::Now();
  base::Time event_time = now + base::Hours(1);
  charge_history_->clock()->set_current_wall_time_for_testing(now);
  CreateChargeHistoryFile(charge_events_dir_, event_time);

  EXPECT_TRUE(ChargeHistoryFileExists(charge_events_dir_, event_time));
  InitNoHistory();
  EXPECT_FALSE(ChargeHistoryFileExists(charge_events_dir_, event_time));
}

TEST_F(AdaptiveChargingControllerTest, TestGetChargeDurationPercentile) {
  InitFullCharge();

  for (int i = 0; i < 15; ++i) {
    EXPECT_EQ(charge_history_->GetChargeDurationPercentile(
                  static_cast<double>(i) / 15.0),
              base::Hours(i + 1));
  }
  EXPECT_EQ(charge_history_->GetChargeDurationPercentile(1.0),
            base::TimeDelta::Max());
}

TEST_F(AdaptiveChargingControllerTest, TestMaxDelayHeuristic) {
  Clock* clock = adaptive_charging_controller_.clock();
  // Set the boot time to a non-zero constant value. This is needed for the
  // delay equality checking below. We can't set to just base::TimeTicks(),
  // since some of the AdaptiveChargingController code conditionally checks
  // that.
  clock->set_current_boot_time_for_testing(base::TimeTicks() +
                                           base::Seconds(1));
  Init();
  SetHoldCharge();

  // Default heuristic with the 30th percentile for charge durations from Charge
  // History. For the 15 durations in Charge History, the 30th percentile is
  // greater than 5 values. This means that the 6th duration (out of 1, 2, ...,
  // 15 hours) is used. 2 hours is subtracted from that based on the
  // `kFinishChargingDelay` value.
  EXPECT_EQ(
      clock->GetCurrentBootTime() + base::Hours(4) +
          AdaptiveChargingController::kFinishChargingDelay,
      adaptive_charging_controller_.get_target_full_charge_time_for_testing());

  // Check that changing `max_delay_percentile_` changes
  // `target_full_charge_time_`. Also check that max delays are correctly
  // modified.
  PowerManagementPolicy policy;
  delegate_.fake_result = {0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0};
  policy.set_adaptive_charging_max_delay_percentile(0.7);
  adaptive_charging_controller_.HandlePolicyChange(policy);
  EXPECT_EQ(
      clock->GetCurrentBootTime() + base::Hours(10) +
          AdaptiveChargingController::kFinishChargingDelay,
      adaptive_charging_controller_.get_target_full_charge_time_for_testing());
}

// Test that the Finch flag for slow charging enables slow charging
// in adaptive charging correctly.
TEST_F(AdaptiveChargingControllerTest, FinchFlagEnablesSlowChargingFeature) {
  // We expect slow charging to be enabled if either the pref is true or Finch
  // flag is enabled. Here, pref is set to false, but enabling the Finch flag
  // should enable slow charging.
  prefs_.SetBool(kSlowAdaptiveChargingEnabledPref, false);
  platform_features_->SetEnabled(kSlowAdaptiveChargingFeatureName, true);
  Init();
  delegate_.fake_result = {0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0};
  adaptive_charging_controller_.set_recheck_delay_for_testing(
      base::TimeDelta());
  base::RunLoop().RunUntilIdle();

  // We expect the charge delay to be 2 hours as the system is predicted to be
  // unplugged in 5 hours, but check for 1.5 hours < `charge_delay` <= 2 hours
  // due to timestamps being slightly off.
  base::TimeDelta charge_delay =
      adaptive_charging_controller_.get_charge_delay_for_testing();
  EXPECT_LE(charge_delay, base::Hours(2));
  EXPECT_GT(charge_delay, base::Hours(1.5));
}

// Test that if slow charging is disabled because the system does not support
// slow charging in Adaptive Charging, `kFinishChargingDelay` is used as the
// charging time from the battery sustain percentage to 100%.
TEST_F(AdaptiveChargingControllerTest, ChargeDelayWhenSlowChargingDisabled) {
  prefs_.SetBool(kSlowAdaptiveChargingEnabledPref, true);
  delegate_.fake_result = {0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0};
  Init();
  adaptive_charging_controller_.set_slow_charging_for_testing(false);
  adaptive_charging_controller_.set_recheck_delay_for_testing(
      base::TimeDelta());
  base::RunLoop().RunUntilIdle();

  // We expect the charge delay to be 2 hours as the system is predicted to be
  // unplugged in 4 hours, but check for 1.5 hours < `charge_delay` <= 2 hours
  // due to timestamps being slightly off.
  base::TimeDelta charge_delay =
      adaptive_charging_controller_.get_charge_delay_for_testing();
  EXPECT_LE(charge_delay, base::Hours(2));
  EXPECT_GT(charge_delay, base::Hours(1.5));
}

// Test that if slow charging is enabled, `kFinishSlowChargingDelay` is used as
// the charging time from the battery sustain percentage to 100%
TEST_F(AdaptiveChargingControllerTest, ChargeDelayWhenSlowChargingEnabled) {
  prefs_.SetBool(kSlowAdaptiveChargingEnabledPref, true);
  delegate_.fake_result = {0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0};
  Init();

  // We expect the charge delay to be 1 hour as the system is predicted to be
  // unplugged in 4 hours, but check for <= 1 hour due to timestamps being
  // slightly off.
  base::TimeDelta charge_delay =
      adaptive_charging_controller_.get_charge_delay_for_testing();
  EXPECT_LE(charge_delay, base::Hours(1));
  EXPECT_GT(charge_delay, base::Hours(0.5));
}

// Test that Adaptive Charging is not stopped when slow charging is started so
// new unplug predictions continue to be made after slow charging has commenced.
TEST_F(AdaptiveChargingControllerTest,
       AdaptiveChargingPersistsWhenSlowCharging) {
  prefs_.SetBool(kSlowAdaptiveChargingEnabledPref, true);
  power_status_.battery_charge_full_design = 6.310;
  power_supply_.set_status(power_status_);
  Init();

  // Change prediction for system unplug time to trigger slow charging.
  delegate_.fake_result = {0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0};
  adaptive_charging_controller_.set_recheck_delay_for_testing(
      base::TimeDelta());
  base::RunLoop().RunUntilIdle();

  // Check that slow charging has commenced and the charge limit has been set.
  EXPECT_FALSE(charge_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_limit, 631);
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);

  // Check that new unplug predictions continue to be made.
  EXPECT_TRUE(recheck_alarm_->IsRunning());
}

// Test that when Adaptive Charging is stopped, slow charging is also stopped
// and the charge limit is reset.
TEST_F(AdaptiveChargingControllerTest,
       StoppingAdaptiveChargingStopsSlowCharging) {
  prefs_.SetBool(kSlowAdaptiveChargingEnabledPref, true);
  power_status_.battery_charge_full_design = 6.310;
  power_supply_.set_status(power_status_);
  Init();

  // Change prediction for system unplug time to trigger slow charging.
  delegate_.fake_result = {0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0};
  adaptive_charging_controller_.set_recheck_delay_for_testing(
      base::TimeDelta());
  base::RunLoop().RunUntilIdle();

  // Change the prediction for when the system would be unplugged to an earlier
  // time to trigger the end of Adaptive Charging.
  delegate_.fake_result[3] = 0.0;
  delegate_.fake_result[1] = 1.0;
  adaptive_charging_controller_.set_recheck_delay_for_testing(
      base::TimeDelta());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(recheck_alarm_->IsRunning());
  EXPECT_FALSE(charge_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_limit, kSlowChargingDisabled);
}

// Test that when the battery is full after slow charging, Adaptive Charging is
// stopped.
TEST_F(AdaptiveChargingControllerTest, BatteryFullStopsSlowAdaptiveCharging) {
  prefs_.SetBool(kSlowAdaptiveChargingEnabledPref, true);
  power_status_.battery_charge_full_design = 6.310;
  power_supply_.set_status(power_status_);
  Init();

  // Change prediction for system unplug time to trigger slow charging.
  delegate_.fake_result = {0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0};
  adaptive_charging_controller_.set_recheck_delay_for_testing(
      base::TimeDelta());
  base::RunLoop().RunUntilIdle();

  // Check that when the battery is full, both slow charging and Adaptive
  // Charging are stopped.
  SetFullCharge();
  EXPECT_FALSE(recheck_alarm_->IsRunning());
  EXPECT_FALSE(charge_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_limit, kSlowChargingDisabled);
}

// Test that when slow charging is enabled and the battery is at the hold
// percent, unplug predictions moving later should not extend the
// target charge finish time.
TEST_F(AdaptiveChargingControllerTest,
       UnplugPredictionMovesLaterDuringBatterySustain) {
  prefs_.SetBool(kSlowAdaptiveChargingEnabledPref, true);
  delegate_.fake_result = {0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0};
  Init();

  base::TimeTicks initial_full_charge_time =
      adaptive_charging_controller_.get_target_full_charge_time_for_testing();

  // Extend the time prediction for when the system would be unplugged by two
  // hours. We expect there to be no change to the target charge finish time.
  delegate_.fake_result[4] = 0.0;
  delegate_.fake_result[6] = 1.0;
  adaptive_charging_controller_.set_recheck_delay_for_testing(
      base::TimeDelta());
  base::RunLoop().RunUntilIdle();
  base::TimeTicks recheck_time =
      adaptive_charging_controller_.get_target_full_charge_time_for_testing();
  EXPECT_EQ(initial_full_charge_time, recheck_time);
  EXPECT_TRUE(charge_alarm_->IsRunning());
  EXPECT_TRUE(recheck_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_lower, kDefaultTestPercent);
  EXPECT_EQ(delegate_.fake_upper, kDefaultTestPercent);
}

// Test that when slow charging is enabled and the battery is at the hold
// percent, unplug predictions moving to `kFinishSlowChargingDelay` of 3 hours
// results in slow charging being started.
TEST_F(AdaptiveChargingControllerTest,
       UnplugPredictionThreeHoursAwayDuringBatterySustain) {
  prefs_.SetBool(kSlowAdaptiveChargingEnabledPref, true);
  power_status_.battery_charge_full_design = 6.310;
  power_supply_.set_status(power_status_);
  delegate_.fake_result = {0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0};
  Init();

  // Move the time prediction to an earlier time such that the duration to
  // unplug time is 3 hours.
  delegate_.fake_result[4] = 0.0;
  delegate_.fake_result[3] = 1.0;
  adaptive_charging_controller_.set_recheck_delay_for_testing(
      base::TimeDelta());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(charge_alarm_->IsRunning());
  EXPECT_TRUE(recheck_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_limit, 631);
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);
}

// Test that when slow charging is enabled and the battery is at the hold
// percent, unplug predictions moving to <= `kFinishChargingDelay` of 2 hours
// results in Adaptive Charging being stopped.
TEST_F(AdaptiveChargingControllerTest,
       UnplugPredictionTwoHoursAwayDuringBatterySustain) {
  prefs_.SetBool(kSlowAdaptiveChargingEnabledPref, true);
  power_status_.battery_charge_full_design = 6.310;
  power_supply_.set_status(power_status_);
  delegate_.fake_result = {0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0};
  Init();

  // Move the time prediction to an earlier time such that the duration to
  // unplug time is 2 hours.
  delegate_.fake_result[4] = 0.0;
  delegate_.fake_result[2] = 1.0;
  adaptive_charging_controller_.set_recheck_delay_for_testing(
      base::TimeDelta());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(charge_alarm_->IsRunning());
  EXPECT_FALSE(recheck_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_limit, kSlowChargingDisabled);
}

// Test that when slow charging has commenced, unplug predictions moving later
// should not extend the target charge finish time.
TEST_F(AdaptiveChargingControllerTest,
       UnplugPredictionMovesLaterWhileSlowCharging) {
  prefs_.SetBool(kSlowAdaptiveChargingEnabledPref, true);
  power_status_.battery_charge_full_design = 6.310;
  power_supply_.set_status(power_status_);
  Init();

  // Change prediction for system unplug time to trigger slow charging.
  delegate_.fake_result = {0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0};
  adaptive_charging_controller_.set_recheck_delay_for_testing(
      base::TimeDelta());
  base::RunLoop().RunUntilIdle();

  // Check that slow charging has commenced.
  EXPECT_FALSE(charge_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_limit, 631);
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);

  // Record the initial target full charge time with `fake_result` as defined
  // above.
  base::TimeTicks initial_full_charge_time =
      adaptive_charging_controller_.get_target_full_charge_time_for_testing();

  // Extend the time prediction for when the system would be unplugged by two
  // hours. We expect there to be no change to the target time for when charging
  // will finish. We do not expect charging to be stopped once it has commenced.
  delegate_.fake_result[3] = 0.0;
  delegate_.fake_result[5] = 1.0;
  adaptive_charging_controller_.set_recheck_delay_for_testing(
      base::TimeDelta());
  base::RunLoop().RunUntilIdle();
  base::TimeTicks recheck_time =
      adaptive_charging_controller_.get_target_full_charge_time_for_testing();
  EXPECT_EQ(initial_full_charge_time, recheck_time);
  EXPECT_TRUE(power_status_.battery_state =
                  PowerSupplyProperties_BatteryState_CHARGING);
  EXPECT_TRUE(recheck_alarm_->IsRunning());
  EXPECT_EQ(delegate_.fake_limit, 631);
  EXPECT_EQ(delegate_.fake_lower, kBatterySustainDisabled);
  EXPECT_EQ(delegate_.fake_upper, kBatterySustainDisabled);
}

// The effects of unplug predictions being rounded down to the hour should not
// cause slow charging to be stopped when there is actually sufficient time for
// slow charging.
TEST_F(AdaptiveChargingControllerTest, SlowChargingNotIncorrectlyStopped) {
  base::TimeDelta time_spent_slow_charging =
      ObtainPredictionOutcome({3.0, 2.5, 2.0, 1.5, 1.0, 0.5});
  EXPECT_EQ(time_spent_slow_charging, base::TimeDelta(base::Hours(3)));
}

// Unplug predictions moving earlier should not cause slow charging to be
// stopped provided total predicted charging time is sufficient for slow
// charging.
TEST_F(AdaptiveChargingControllerTest,
       SlowChargingNotStoppedWhenTotalChargeTimeReducedButSufficient) {
  // We reduce total predicted charging time by 0.5 hour after 0.5 hour of slow
  // charging.
  base::TimeDelta time_spent_slow_charging =
      ObtainPredictionOutcome({3.5, 2.5, 2.0, 1.5, 1.0, 0.5});
  EXPECT_EQ(time_spent_slow_charging, base::TimeDelta(base::Hours(3)));
}

// Unplug predictions moving earlier should cause slow charging to be stopped
// once total predicted charging time is insufficient for slow charging.
TEST_F(AdaptiveChargingControllerTest,
       SlowChargingStoppedWhenTotalChargeTimeReducedAndInsufficient) {
  // We reduce total predicted charging time by 0.5 hour after 0.5 hour of slow
  // charging.
  base::TimeDelta time_spent_slow_charging =
      ObtainPredictionOutcome({3.0, 2.0, 1.5, 1.0, 0.5});
  EXPECT_EQ(time_spent_slow_charging, base::TimeDelta(base::Hours(1)));
}

}  // namespace power_manager::policy
