// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/metrics_collector.h"

#include <stdint.h>

#include <cmath>
#include <iterator>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/format_macros.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/timer/timer.h>
#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

#include "metrics/fake_metrics_library.h"
#include "power_manager/common/fake_prefs.h"
#include "power_manager/common/metrics_constants.h"
#include "power_manager/common/metrics_sender.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/policy/backlight_controller_stub.h"
#include "power_manager/powerd/policy/suspender.h"
#include "power_manager/powerd/system/power_supply.h"
#include "power_manager/powerd/testing/test_environment.h"

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Mock;
using ::testing::Return;
using ::testing::StrictMock;

namespace power_manager::metrics {

class MetricsCollectorTest : public TestEnvironment {
 public:
  MetricsCollectorTest() : metrics_sender_(metrics_lib_) {
    collector_.clock_.set_current_time_for_testing(base::TimeTicks() +
                                                   base::Microseconds(1000));
    collector_.clock_.set_current_boot_time_for_testing(
        base::TimeTicks() + base::Microseconds(2000));
    CHECK(temp_root_dir_.CreateUniqueTempDir());
    collector_.set_prefix_path_for_testing(temp_root_dir_.GetPath());

    power_status_.battery_percentage = 100.0;
    power_status_.battery_charge_full = 100.0;
    power_status_.battery_charge_full_design = 100.0;
    power_status_.battery_is_present = true;
    power_status_.line_power_type = "Mains";
  }

 protected:
  // Initializes |collector_|.
  void Init() {
    collector_.Init(&prefs_, &display_backlight_controller_,
                    &keyboard_backlight_controller_, power_status_,
                    first_run_after_boot_);
  }

  // Advances both the monotonically-increasing time and wall time by
  // |interval|.
  void AdvanceTime(base::TimeDelta interval) {
    collector_.clock_.set_current_time_for_testing(
        collector_.clock_.GetCurrentTime() + interval);
    collector_.clock_.set_current_boot_time_for_testing(
        collector_.clock_.GetCurrentBootTime() + interval);
  }

  base::TimeTicks GetCurrentBootTime() {
    return collector_.clock_.GetCurrentBootTime();
  }

  // Adds expectations to ignore all metrics sent by HandleSessionStateChange()
  // (except ones listed in |metrics_to_test_|).
  void IgnoreHandleSessionStateChangeMetrics() {
    IgnoreEnumMetric(MetricsCollector::AppendPowerSourceToEnumName(
        kBatteryRemainingAtStartOfSessionName, PowerSource::AC));
    IgnoreEnumMetric(MetricsCollector::AppendPowerSourceToEnumName(
        kBatteryRemainingAtStartOfSessionName, PowerSource::BATTERY));
    IgnoreEnumMetric(MetricsCollector::AppendPowerSourceToEnumName(
        kBatteryRemainingAtEndOfSessionName, PowerSource::AC));
    IgnoreEnumMetric(MetricsCollector::AppendPowerSourceToEnumName(
        kBatteryRemainingAtEndOfSessionName, PowerSource::BATTERY));
    IgnoreMetric(kLengthOfSessionName);
    IgnoreMetric(kNumberOfAlsAdjustmentsPerSessionName);
    IgnoreMetric(MetricsCollector::AppendPowerSourceToEnumName(
        kUserBrightnessAdjustmentsPerSessionName, PowerSource::AC));
    IgnoreMetric(MetricsCollector::AppendPowerSourceToEnumName(
        kUserBrightnessAdjustmentsPerSessionName, PowerSource::BATTERY));
  }

  // Adds expectations to ignore all metrics sent by HandlePowerStatusUpdate()
  // (except ones listed in |metrics_to_test_|).
  void IgnoreHandlePowerStatusUpdateMetrics() {
    IgnoreMetric(kNumOfSessionsPerChargeName);
    IgnoreEnumMetric(kBatteryRemainingWhenChargeStartsName);
    IgnoreEnumMetric(kBatteryChargeHealthName);
    IgnoreMetric(std::string(kBatteryCapacityName) +
                 kBatteryCapacityActualSuffix);
    IgnoreMetric(std::string(kBatteryCapacityName) +
                 kBatteryCapacityDesignSuffix);
    IgnoreMetric(kBatteryDischargeRateName);
    IgnoreMetric(kBatteryDischargeRateWhileHibernatedName);
    IgnoreMetric(kBatteryDischargeRateWhileSuspendedName);
    IgnoreMetric(std::string(kBatteryLifeName) + kBatteryCapacityActualSuffix);
    IgnoreMetric(std::string(kBatteryLifeName) + kBatteryCapacityDesignSuffix);
    IgnoreMetric(std::string(kBatteryLifeWhileSuspendedName) +
                 kBatteryCapacityActualSuffix);
    IgnoreMetric(std::string(kBatteryLifeWhileSuspendedName) +
                 kBatteryCapacityDesignSuffix);
    IgnoreEnumMetric(kBatteryInfoSampleName);
    IgnoreEnumMetric(kPowerSupplyTypeName);
    IgnoreEnumMetric(kPowerSupplyMaxVoltageName);
    IgnoreEnumMetric(kPowerSupplyMaxPowerName);
    IgnoreEnumMetric(kConnectedChargingPortsName);
  }

  // Updates |power_status_|'s |line_power_on| member and passes it to
  // HandlePowerStatusUpdate().
  void UpdatePowerStatusLinePower(bool line_power_on) {
    power_status_.line_power_on = line_power_on;
    collector_.HandlePowerStatusUpdate(power_status_);
  }

  // Adds a metrics library mock expectation that the specified metric
  // will be generated.
  void ExpectMetric(
      const std::string& name, int sample, int min, int max, int buckets) {
    EXPECT_CALL(metrics_lib_, SendToUMA(name, sample, min, max, buckets))
        .Times(1)
        .WillOnce(Return(true))
        .RetiresOnSaturation();
  }

  // Adds a metrics library mock expectation that the specified enum
  // metric will be generated.
  void ExpectEnumMetric(const std::string& name, int sample, int max) {
    EXPECT_CALL(metrics_lib_, SendEnumToUMA(name, sample, max))
        .Times(1)
        .WillOnce(Return(true))
        .RetiresOnSaturation();
  }

  // Ignores an arbitrary number of reports of |name|.
  void IgnoreMetric(const std::string& name) {
    if (metrics_to_test_.count(name))
      return;
    EXPECT_CALL(metrics_lib_, SendToUMA(name, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(true));
  }

  // Ignores an arbitrary number of reports of |name|.
  void IgnoreEnumMetric(const std::string& name) {
    if (metrics_to_test_.count(name))
      return;
    EXPECT_CALL(metrics_lib_, SendEnumToUMA(name, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(true));
  }

  void ExpectBatteryDischargeRateMetric(int discharge_rate,
                                        int battery_life_actual,
                                        int battery_life_design) {
    ExpectMetric(kBatteryDischargeRateName, discharge_rate,
                 kBatteryDischargeRateMin, kBatteryDischargeRateMax,
                 kDefaultDischargeBuckets);
    ExpectMetric(std::string(kBatteryLifeName) + kBatteryCapacityActualSuffix,
                 battery_life_actual, kBatteryLifeMin, kBatteryLifeMax,
                 kDefaultDischargeBuckets);
    ExpectMetric(std::string(kBatteryLifeName) + kBatteryCapacityDesignSuffix,
                 battery_life_design, kBatteryLifeMin, kBatteryLifeMax,
                 kDefaultDischargeBuckets);
  }

  void ExpectNumOfSessionsPerChargeMetric(int sample) {
    ExpectMetric(kNumOfSessionsPerChargeName, sample,
                 kNumOfSessionsPerChargeMin, kNumOfSessionsPerChargeMax,
                 kDefaultBuckets);
  }

  // Returns |orig| rooted within the temporary root dir created for testing.
  base::FilePath GetPath(const base::FilePath& orig) const {
    return temp_root_dir_.GetPath().Append(orig.value().substr(1));
  }

  FakePrefs prefs_;
  policy::BacklightControllerStub display_backlight_controller_;
  policy::BacklightControllerStub keyboard_backlight_controller_;
  system::PowerStatus power_status_;
  bool first_run_after_boot_ = false;

  // StrictMock turns all unexpected calls into hard failures.
  StrictMock<MetricsLibraryMock> metrics_lib_;
  MetricsSender metrics_sender_;

  MetricsCollector collector_;

  // Names of metrics that will not be ignored by calls to Ignore*(). Tests
  // should insert the metrics that they're testing into this set and then call
  // Ignore*Metrics() (and call it again whenever expectations are cleared).
  std::set<std::string> metrics_to_test_;

  base::ScopedTempDir temp_root_dir_;
};

TEST_F(MetricsCollectorTest, BacklightLevel) {
  power_status_.line_power_on = false;
  Init();
  ASSERT_TRUE(collector_.generate_backlight_metrics_timer_.IsRunning());
  collector_.HandleScreenDimmedChange(true, base::TimeTicks::Now());
  collector_.GenerateBacklightLevelMetrics();
  Mock::VerifyAndClearExpectations(&metrics_lib_);

  const int64_t kCurrentDisplayPercent = 57;
  display_backlight_controller_.set_percent(kCurrentDisplayPercent);
  const int64_t kCurrentKeyboardPercent = 43;
  keyboard_backlight_controller_.set_percent(kCurrentKeyboardPercent);

  collector_.HandleScreenDimmedChange(false, base::TimeTicks::Now());
  ExpectEnumMetric(MetricsCollector::AppendPowerSourceToEnumName(
                       kBacklightLevelName, PowerSource::BATTERY),
                   kCurrentDisplayPercent, kMaxPercent);
  ExpectEnumMetric(kKeyboardBacklightLevelName, kCurrentKeyboardPercent,
                   kMaxPercent);
  collector_.GenerateBacklightLevelMetrics();

  power_status_.line_power_on = true;
  IgnoreHandlePowerStatusUpdateMetrics();
  collector_.HandlePowerStatusUpdate(power_status_);
  ExpectEnumMetric(MetricsCollector::AppendPowerSourceToEnumName(
                       kBacklightLevelName, PowerSource::AC),
                   kCurrentDisplayPercent, kMaxPercent);
  ExpectEnumMetric(kKeyboardBacklightLevelName, kCurrentKeyboardPercent,
                   kMaxPercent);
  collector_.GenerateBacklightLevelMetrics();

  std::vector<bool> line_power_on_states{true, false};
  std::vector<privacy_screen::PrivacyScreenSetting_PrivacyScreenState>
      privacy_screen_states{
          privacy_screen::PrivacyScreenSetting_PrivacyScreenState_DISABLED,
          privacy_screen::PrivacyScreenSetting_PrivacyScreenState_ENABLED};
  for (const auto& line_power_on : line_power_on_states) {
    for (const auto& state : privacy_screen_states) {
      const PowerSource source =
          line_power_on ? PowerSource::AC : PowerSource::BATTERY;
      power_status_.line_power_on = line_power_on;
      IgnoreHandlePowerStatusUpdateMetrics();
      collector_.HandlePowerStatusUpdate(power_status_);
      collector_.HandlePrivacyScreenStateChange(state);
      ExpectEnumMetric(MetricsCollector::AppendPowerSourceToEnumName(
                           kBacklightLevelName, source),
                       kCurrentDisplayPercent, kMaxPercent);
      ExpectEnumMetric(MetricsCollector::AppendPowerSourceToEnumName(
                           MetricsCollector::AppendPrivacyScreenStateToEnumName(
                               kBacklightLevelName, state),
                           source),
                       kCurrentDisplayPercent, kMaxPercent);
      ExpectEnumMetric(kKeyboardBacklightLevelName, kCurrentKeyboardPercent,
                       kMaxPercent);
      collector_.GenerateBacklightLevelMetrics();
    }
  }
}

TEST_F(MetricsCollectorTest, BatteryDischargeRate) {
  power_status_.line_power_on = false;
  prefs_.SetDouble(kLowBatteryShutdownPercentPref, 10.0);
  Init();

  metrics_to_test_.insert(kBatteryDischargeRateName);
  metrics_to_test_.insert(std::string(kBatteryLifeName) +
                          kBatteryCapacityActualSuffix);
  metrics_to_test_.insert(std::string(kBatteryLifeName) +
                          kBatteryCapacityDesignSuffix);

  IgnoreHandlePowerStatusUpdateMetrics();

  // This much time must elapse before the discharge rate will be reported
  // again.
  const base::TimeDelta interval = kBatteryDischargeRateInterval;

  power_status_.battery_energy_full = 50.0;
  power_status_.battery_energy_full_design = 60.0;

  power_status_.battery_energy_rate = 5.0;
  int actual = round(60.0 * 50.0 / 5.0 * 0.9);
  int design = round(60.0 * 60.0 / 5.0 * 0.9);
  ExpectBatteryDischargeRateMetric(5000, actual, design);
  collector_.HandlePowerStatusUpdate(power_status_);

  power_status_.battery_energy_rate = 4.5;
  actual = round(60.0 * 50.0 / 4.5 * 0.9);
  design = round(60.0 * 60.0 / 4.5 * 0.9);
  ExpectBatteryDischargeRateMetric(4500, actual, design);
  AdvanceTime(interval);
  collector_.HandlePowerStatusUpdate(power_status_);

  power_status_.battery_energy_rate = 6.4;
  actual = round(60.0 * 50.0 / 6.4 * 0.9);
  design = round(60.0 * 60.0 / 6.4 * 0.9);
  ExpectBatteryDischargeRateMetric(6400, actual, design);
  AdvanceTime(interval);
  collector_.HandlePowerStatusUpdate(power_status_);

  Mock::VerifyAndClearExpectations(&metrics_lib_);
  IgnoreHandlePowerStatusUpdateMetrics();

  // Another update before the full interval has elapsed shouldn't result in
  // another report.
  AdvanceTime(interval / 2);
  collector_.HandlePowerStatusUpdate(power_status_);

  // Neither should a call while the energy rate is negative.
  AdvanceTime(interval);
  power_status_.battery_energy_rate = -4.0;
  collector_.HandlePowerStatusUpdate(power_status_);

  // Ditto for a call while the system is on AC power.
  power_status_.line_power_on = true;
  power_status_.battery_energy_rate = 4.0;
  collector_.HandlePowerStatusUpdate(power_status_);
}

TEST_F(MetricsCollectorTest, BatteryInfoWhenChargeStarts) {
  const double kBatteryPercentages[] = {10.1, 10.7, 82.4, 82.5, 100.0};

  power_status_.line_power_on = false;
  power_status_.battery_charge_full_design = 100.0;
  power_status_.battery_energy_full_design = 100.0;
  Init();

  metrics_to_test_.insert(kBatteryRemainingWhenChargeStartsName);
  metrics_to_test_.insert(kBatteryChargeHealthName);
  metrics_to_test_.insert(std::string(kBatteryCapacityName) +
                          kBatteryCapacityActualSuffix);
  metrics_to_test_.insert(std::string(kBatteryCapacityName) +
                          kBatteryCapacityDesignSuffix);

  for (const auto& percentage : kBatteryPercentages) {
    IgnoreHandlePowerStatusUpdateMetrics();

    power_status_.line_power_on = false;
    power_status_.battery_charge_full = percentage;
    power_status_.battery_energy_full = percentage;
    power_status_.battery_percentage = percentage;
    collector_.HandlePowerStatusUpdate(power_status_);

    power_status_.line_power_on = true;
    ExpectEnumMetric(kBatteryRemainingWhenChargeStartsName,
                     round(power_status_.battery_percentage), kMaxPercent);
    ExpectEnumMetric(kBatteryChargeHealthName,
                     round(100.0 * power_status_.battery_charge_full /
                           power_status_.battery_charge_full_design),
                     kBatteryChargeHealthMax);
    ExpectMetric(
        std::string(kBatteryCapacityName) + kBatteryCapacityActualSuffix,
        round(1000.0 * power_status_.battery_energy_full), kBatteryCapacityMin,
        kBatteryCapacityMax, kDefaultBuckets);
    ExpectMetric(
        std::string(kBatteryCapacityName) + kBatteryCapacityDesignSuffix,
        round(1000.0 * power_status_.battery_energy_full_design),
        kBatteryCapacityMin, kBatteryCapacityMax, kDefaultBuckets);
    collector_.HandlePowerStatusUpdate(power_status_);

    Mock::VerifyAndClearExpectations(&metrics_lib_);
  }
}

TEST_F(MetricsCollectorTest, SessionStartOrStop) {
  const uint kAlsAdjustments[] = {0, 100};
  const uint kUserAdjustments[] = {0, 200};
  const double kBatteryPercentages[] = {10.5, 23.0};
  const int kSessionSecs[] = {900, kLengthOfSessionMax + 10};
  ASSERT_EQ(std::size(kAlsAdjustments), std::size(kUserAdjustments));
  ASSERT_EQ(std::size(kAlsAdjustments), std::size(kBatteryPercentages));
  ASSERT_EQ(std::size(kAlsAdjustments), std::size(kSessionSecs));

  power_status_.line_power_on = false;
  Init();

  for (size_t i = 0; i < std::size(kAlsAdjustments); ++i) {
    IgnoreHandlePowerStatusUpdateMetrics();
    power_status_.battery_percentage = kBatteryPercentages[i];
    ExpectEnumMetric(
        MetricsCollector::AppendPowerSourceToEnumName(
            kBatteryRemainingAtStartOfSessionName, PowerSource::BATTERY),
        round(kBatteryPercentages[i]), kMaxPercent);
    collector_.HandlePowerStatusUpdate(power_status_);
    collector_.HandleSessionStateChange(SessionState::STARTED);
    Mock::VerifyAndClearExpectations(&metrics_lib_);

    ExpectEnumMetric(
        MetricsCollector::AppendPowerSourceToEnumName(
            kBatteryRemainingAtEndOfSessionName, PowerSource::BATTERY),
        round(kBatteryPercentages[i]), kMaxPercent);

    display_backlight_controller_.set_num_als_adjustments(kAlsAdjustments[i]);
    display_backlight_controller_.set_num_user_adjustments(kUserAdjustments[i]);
    ExpectMetric(kNumberOfAlsAdjustmentsPerSessionName, kAlsAdjustments[i],
                 kNumberOfAlsAdjustmentsPerSessionMin,
                 kNumberOfAlsAdjustmentsPerSessionMax, kDefaultBuckets);
    ExpectMetric(
        MetricsCollector::AppendPowerSourceToEnumName(
            kUserBrightnessAdjustmentsPerSessionName, PowerSource::BATTERY),
        kUserAdjustments[i], kUserBrightnessAdjustmentsPerSessionMin,
        kUserBrightnessAdjustmentsPerSessionMax, kDefaultBuckets);

    AdvanceTime(base::Seconds(kSessionSecs[i]));
    ExpectMetric(kLengthOfSessionName, kSessionSecs[i], kLengthOfSessionMin,
                 kLengthOfSessionMax, kDefaultBuckets);

    collector_.HandleSessionStateChange(SessionState::STOPPED);
    Mock::VerifyAndClearExpectations(&metrics_lib_);
  }
}

TEST_F(MetricsCollectorTest, GenerateNumOfSessionsPerChargeMetric) {
  metrics_to_test_.insert(kNumOfSessionsPerChargeName);
  power_status_.line_power_on = false;
  Init();

  IgnoreHandlePowerStatusUpdateMetrics();
  UpdatePowerStatusLinePower(true);
  Mock::VerifyAndClearExpectations(&metrics_lib_);

  // If the session is already started when going off line power, it should be
  // counted. Additional power status updates that don't describe a power source
  // change shouldn't increment the count.
  IgnoreHandleSessionStateChangeMetrics();
  collector_.HandleSessionStateChange(SessionState::STARTED);
  IgnoreHandlePowerStatusUpdateMetrics();
  UpdatePowerStatusLinePower(false);
  UpdatePowerStatusLinePower(false);
  UpdatePowerStatusLinePower(false);
  ExpectNumOfSessionsPerChargeMetric(1);
  UpdatePowerStatusLinePower(true);
  Mock::VerifyAndClearExpectations(&metrics_lib_);

  // Sessions that start while on battery power should also be counted.
  IgnoreHandleSessionStateChangeMetrics();
  collector_.HandleSessionStateChange(SessionState::STOPPED);
  IgnoreHandlePowerStatusUpdateMetrics();
  UpdatePowerStatusLinePower(false);
  collector_.HandleSessionStateChange(SessionState::STARTED);
  collector_.HandleSessionStateChange(SessionState::STOPPED);
  collector_.HandleSessionStateChange(SessionState::STARTED);
  collector_.HandleSessionStateChange(SessionState::STOPPED);
  collector_.HandleSessionStateChange(SessionState::STARTED);
  ExpectNumOfSessionsPerChargeMetric(3);
  UpdatePowerStatusLinePower(true);
  Mock::VerifyAndClearExpectations(&metrics_lib_);

  // Check that the pref is used, so the count will persist across reboots.
  IgnoreHandlePowerStatusUpdateMetrics();
  UpdatePowerStatusLinePower(false);
  prefs_.SetInt64(kNumSessionsOnCurrentChargePref, 5);
  ExpectNumOfSessionsPerChargeMetric(5);
  UpdatePowerStatusLinePower(true);
  Mock::VerifyAndClearExpectations(&metrics_lib_);

  // Negative values in the pref should be ignored.
  prefs_.SetInt64(kNumSessionsOnCurrentChargePref, -2);
  IgnoreHandlePowerStatusUpdateMetrics();
  UpdatePowerStatusLinePower(false);
  ExpectNumOfSessionsPerChargeMetric(1);
  UpdatePowerStatusLinePower(true);
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

TEST_F(MetricsCollectorTest, SendEnumMetric) {
  Init();
  ExpectEnumMetric("Dummy.EnumMetric", 50, 200);
  EXPECT_TRUE(SendEnumMetric("Dummy.EnumMetric", 50, 200));

  // Out-of-bounds values should be capped.
  ExpectEnumMetric("Dummy.EnumMetric2", 20, 20);
  EXPECT_TRUE(SendEnumMetric("Dummy.EnumMetric2", 21, 20));
}

TEST_F(MetricsCollectorTest, SendMetric) {
  Init();
  ExpectMetric("Dummy.Metric", 3, 1, 100, 50);
  EXPECT_TRUE(SendMetric("Dummy.Metric", 3, 1, 100, 50));

  // Out-of-bounds values should not be capped (so they can instead land in the
  // underflow or overflow bucket).
  ExpectMetric("Dummy.Metric2", -1, 0, 20, 4);
  EXPECT_TRUE(SendMetric("Dummy.Metric2", -1, 0, 20, 4));
  ExpectMetric("Dummy.Metric3", 30, 5, 25, 6);
  EXPECT_TRUE(SendMetric("Dummy.Metric3", 30, 5, 25, 6));
}

TEST_F(MetricsCollectorTest, SendMetricWithPowerSource) {
  power_status_.line_power_on = false;
  Init();
  ExpectMetric("Dummy.MetricOnBattery", 3, 1, 100, 50);
  EXPECT_TRUE(
      collector_.SendMetricWithPowerSource("Dummy.Metric", 3, 1, 100, 50));

  IgnoreHandlePowerStatusUpdateMetrics();
  power_status_.line_power_on = true;
  collector_.HandlePowerStatusUpdate(power_status_);
  ExpectMetric("Dummy.MetricOnAC", 6, 2, 200, 80);
  EXPECT_TRUE(
      collector_.SendMetricWithPowerSource("Dummy.Metric", 6, 2, 200, 80));
}

TEST_F(MetricsCollectorTest, PowerButtonDownMetric) {
  Init();

  // We should ignore a button release that wasn't preceded by a press.
  collector_.HandlePowerButtonEvent(ButtonState::UP);
  Mock::VerifyAndClearExpectations(&metrics_lib_);

  // Presses that are followed by additional presses should also be ignored.
  collector_.HandlePowerButtonEvent(ButtonState::DOWN);
  collector_.HandlePowerButtonEvent(ButtonState::DOWN);
  Mock::VerifyAndClearExpectations(&metrics_lib_);

  // Send a regular sequence of events and check that the duration is reported.
  collector_.HandlePowerButtonEvent(ButtonState::DOWN);
  const base::TimeDelta kDuration = base::Milliseconds(243);
  AdvanceTime(kDuration);
  ExpectMetric(kPowerButtonDownTimeName, kDuration.InMilliseconds(),
               kPowerButtonDownTimeMin, kPowerButtonDownTimeMax,
               kDefaultBuckets);
  collector_.HandlePowerButtonEvent(ButtonState::UP);
}

TEST_F(MetricsCollectorTest, AmbientLightResumeMetric) {
  Init();
  ASSERT_TRUE(display_backlight_controller_
                  .ambient_light_metrics_callback_registered());

  ExpectMetric(kAmbientLightOnResumeName, 2400, kAmbientLightOnResumeMin,
               kAmbientLightOnResumeMax, kDefaultBuckets);
  collector_.GenerateAmbientLightResumeMetrics(2400);
}

TEST_F(MetricsCollectorTest, GatherDarkResumeMetrics) {
  Init();

  std::vector<policy::Suspender::DarkResumeInfo> wake_durations;
  base::TimeDelta suspend_duration;
  base::TimeDelta kTimeDelta1 = base::Seconds(2);
  base::TimeDelta kTimeDelta2 = base::Seconds(6);
  base::TimeDelta kTimeDelta3 = base::Milliseconds(573);
  base::TimeDelta kTimeDelta4 = base::Seconds(7);
  std::string kWakeReason1 = "WiFi.Pattern";
  std::string kWakeReason2 = "WiFi.Disconnect";
  std::string kWakeReason3 = "WiFi.SSID";
  std::string kWakeReason4 = "Other";
  std::string kExpectedHistogramPrefix = "Power.DarkResumeWakeDurationMs.";
  std::string kExpectedHistogram1 = kExpectedHistogramPrefix + kWakeReason1;
  std::string kExpectedHistogram2 = kExpectedHistogramPrefix + kWakeReason2;
  std::string kExpectedHistogram3 = kExpectedHistogramPrefix + kWakeReason3;
  std::string kExpectedHistogram4 = kExpectedHistogramPrefix + kWakeReason4;

  // First test the basic case.
  wake_durations.emplace_back(kWakeReason1, kTimeDelta1);
  wake_durations.emplace_back(kWakeReason2, kTimeDelta2);
  wake_durations.emplace_back(kWakeReason3, kTimeDelta3);
  wake_durations.emplace_back(kWakeReason4, kTimeDelta4);

  suspend_duration = base::Hours(2);

  ExpectMetric(kDarkResumeWakeupsPerHourName,
               wake_durations.size() / suspend_duration.InHours(),
               kDarkResumeWakeupsPerHourMin, kDarkResumeWakeupsPerHourMax,
               kDefaultBuckets);
  for (const auto& pair : wake_durations) {
    const base::TimeDelta& duration = pair.second;
    ExpectMetric(kDarkResumeWakeDurationMsName, duration.InMilliseconds(),
                 kDarkResumeWakeDurationMsMin, kDarkResumeWakeDurationMsMax,
                 kDefaultBuckets);
  }
  ExpectMetric(kExpectedHistogram1, kTimeDelta1.InMilliseconds(),
               kDarkResumeWakeDurationMsMin, kDarkResumeWakeDurationMsMax,
               kDefaultBuckets);
  ExpectMetric(kExpectedHistogram2, kTimeDelta2.InMilliseconds(),
               kDarkResumeWakeDurationMsMin, kDarkResumeWakeDurationMsMax,
               kDefaultBuckets);
  ExpectMetric(kExpectedHistogram3, kTimeDelta3.InMilliseconds(),
               kDarkResumeWakeDurationMsMin, kDarkResumeWakeDurationMsMax,
               kDefaultBuckets);
  ExpectMetric(kExpectedHistogram4, kTimeDelta4.InMilliseconds(),
               kDarkResumeWakeDurationMsMin, kDarkResumeWakeDurationMsMax,
               kDefaultBuckets);

  collector_.GenerateDarkResumeMetrics(wake_durations, suspend_duration);

  // If the suspend lasts for less than an hour, the wakeups per hour should be
  // scaled up.
  Mock::VerifyAndClearExpectations(&metrics_lib_);
  wake_durations.clear();

  wake_durations.emplace_back(kWakeReason1, base::Milliseconds(359));
  suspend_duration = base::Minutes(13);

  IgnoreMetric(kDarkResumeWakeDurationMsName);
  IgnoreMetric(kExpectedHistogram1);
  ExpectMetric(kDarkResumeWakeupsPerHourName, 4, kDarkResumeWakeupsPerHourMin,
               kDarkResumeWakeupsPerHourMax, kDefaultBuckets);

  collector_.GenerateDarkResumeMetrics(wake_durations, suspend_duration);
}

TEST_F(MetricsCollectorTest, BatteryDischargeRateWhileSuspended) {
  const double kEnergyBeforeSuspend = 60;
  const double kEnergyAfterResume = 50;
  const base::TimeDelta kSuspendDuration = base::Hours(1);

  metrics_to_test_.insert(kBatteryDischargeRateWhileSuspendedName);
  metrics_to_test_.insert(kBatteryDischargeRateWhileHibernatedName);
  metrics_to_test_.insert(std::string(kBatteryLifeWhileSuspendedName) +
                          kBatteryCapacityActualSuffix);
  metrics_to_test_.insert(std::string(kBatteryLifeWhileSuspendedName) +
                          kBatteryCapacityDesignSuffix);

  power_status_.line_power_on = false;
  power_status_.battery_energy = kEnergyAfterResume;
  power_status_.battery_energy_full = 50.0;
  power_status_.battery_energy_full_design = 60.0;
  Init();

  // We shouldn't send a sample if we haven't suspended.
  IgnoreHandlePowerStatusUpdateMetrics();
  collector_.HandlePowerStatusUpdate(power_status_);
  Mock::VerifyAndClearExpectations(&metrics_lib_);

  // Ditto if the system is on AC before suspending...
  power_status_.line_power_on = true;
  power_status_.battery_energy = kEnergyBeforeSuspend;
  IgnoreHandlePowerStatusUpdateMetrics();
  collector_.HandlePowerStatusUpdate(power_status_);
  collector_.PrepareForSuspend();
  AdvanceTime(kSuspendDuration);
  ExpectMetric(kSuspendAttemptsBeforeSuccessName, 1, kSuspendAttemptsMin,
               kSuspendAttemptsMax, kSuspendAttemptsBuckets);
  collector_.HandleResume(1, false);
  power_status_.line_power_on = false;
  power_status_.battery_energy = kEnergyAfterResume;
  collector_.HandlePowerStatusUpdate(power_status_);
  Mock::VerifyAndClearExpectations(&metrics_lib_);

  // ... or after resuming...
  power_status_.line_power_on = false;
  power_status_.battery_energy = kEnergyBeforeSuspend;
  IgnoreHandlePowerStatusUpdateMetrics();
  collector_.HandlePowerStatusUpdate(power_status_);
  collector_.PrepareForSuspend();
  AdvanceTime(kSuspendDuration);
  ExpectMetric(kSuspendAttemptsBeforeSuccessName, 2, kSuspendAttemptsMin,
               kSuspendAttemptsMax, kSuspendAttemptsBuckets);
  collector_.HandleResume(2, false);
  power_status_.line_power_on = true;
  power_status_.battery_energy = kEnergyAfterResume;
  collector_.HandlePowerStatusUpdate(power_status_);
  Mock::VerifyAndClearExpectations(&metrics_lib_);

  // ... or if the battery's energy increased while the system was
  // suspended (i.e. it was temporarily connected to AC while suspended).
  power_status_.line_power_on = false;
  power_status_.battery_energy = kEnergyBeforeSuspend;
  IgnoreHandlePowerStatusUpdateMetrics();
  collector_.HandlePowerStatusUpdate(power_status_);
  collector_.PrepareForSuspend();
  AdvanceTime(kSuspendDuration);
  ExpectMetric(kSuspendAttemptsBeforeSuccessName, 1, kSuspendAttemptsMin,
               kSuspendAttemptsMax, kSuspendAttemptsBuckets);
  collector_.HandleResume(1, false);
  power_status_.battery_energy = kEnergyBeforeSuspend + 5.0;
  collector_.HandlePowerStatusUpdate(power_status_);
  Mock::VerifyAndClearExpectations(&metrics_lib_);

  // The sample also shouldn't be reported if the system wasn't suspended
  // for very long.
  power_status_.battery_energy = kEnergyBeforeSuspend;
  IgnoreHandlePowerStatusUpdateMetrics();
  collector_.HandlePowerStatusUpdate(power_status_);
  collector_.PrepareForSuspend();
  AdvanceTime(kBatteryDischargeRateWhileSuspendedMinSuspend - base::Seconds(1));
  ExpectMetric(kSuspendAttemptsBeforeSuccessName, 1, kSuspendAttemptsMin,
               kSuspendAttemptsMax, kSuspendAttemptsBuckets);
  collector_.HandleResume(1, false);
  power_status_.battery_energy = kEnergyAfterResume;
  collector_.HandlePowerStatusUpdate(power_status_);
  Mock::VerifyAndClearExpectations(&metrics_lib_);

  // The sample should be reported if the energy decreased over a long
  // enough time.
  power_status_.battery_energy = kEnergyBeforeSuspend;
  IgnoreHandlePowerStatusUpdateMetrics();
  collector_.HandlePowerStatusUpdate(power_status_);
  collector_.PrepareForSuspend();
  AdvanceTime(kSuspendDuration);
  ExpectMetric(kSuspendAttemptsBeforeSuccessName, 1, kSuspendAttemptsMin,
               kSuspendAttemptsMax, kSuspendAttemptsBuckets);
  collector_.HandleResume(1, false);
  power_status_.battery_energy = kEnergyAfterResume;
  const int rate_mw = static_cast<int>(
      round(1000 * (kEnergyBeforeSuspend - kEnergyAfterResume) /
            (kSuspendDuration.InSecondsF() / 3600)));
  ExpectMetric(kBatteryDischargeRateWhileSuspendedName, rate_mw,
               kBatteryDischargeRateWhileSuspendedMin,
               kBatteryDischargeRateWhileSuspendedMax,
               kDefaultDischargeBuckets);
  ExpectMetric(std::string(kBatteryLifeWhileSuspendedName) +
                   kBatteryCapacityActualSuffix,
               round(1000.0 * 50.0 / rate_mw), kBatteryLifeWhileSuspendedMin,
               kBatteryLifeWhileSuspendedMax, kDefaultDischargeBuckets);
  ExpectMetric(std::string(kBatteryLifeWhileSuspendedName) +
                   kBatteryCapacityDesignSuffix,
               round(1000.0 * 60.0 / rate_mw), kBatteryLifeWhileSuspendedMin,
               kBatteryLifeWhileSuspendedMax, kDefaultDischargeBuckets);
  collector_.HandlePowerStatusUpdate(power_status_);

  // The name of the metric should change to hibernate if this was a resume from
  // hibernation.
  // We also shouldn't report Power.BatteryLifeWhileSuspended metrics.
  power_status_.battery_energy = kEnergyBeforeSuspend;
  IgnoreHandlePowerStatusUpdateMetrics();
  collector_.HandlePowerStatusUpdate(power_status_);
  collector_.PrepareForSuspend();
  AdvanceTime(kSuspendDuration);
  ExpectMetric(kHibernateAttemptsBeforeSuccessName, 1, kSuspendAttemptsMin,
               kSuspendAttemptsMax, kSuspendAttemptsBuckets);
  collector_.HandleResume(1, true);
  power_status_.battery_energy = kEnergyAfterResume;
  ExpectMetric(kBatteryDischargeRateWhileHibernatedName, rate_mw,
               kBatteryDischargeRateWhileSuspendedMin,
               kBatteryDischargeRateWhileSuspendedMax,
               kDefaultDischargeBuckets);
  collector_.HandlePowerStatusUpdate(power_status_);
}

TEST_F(MetricsCollectorTest, PowerSupplyMaxVoltageAndPower) {
  metrics_to_test_ = {
      kPowerSupplyMaxVoltageName,
      kPowerSupplyMaxPowerName,
  };
  IgnoreHandlePowerStatusUpdateMetrics();
  power_status_.line_power_on = false;
  Init();

  power_status_.line_power_on = true;
  power_status_.line_power_max_voltage = 4.2;
  power_status_.line_power_max_current = 12.7;
  ExpectEnumMetric(
      kPowerSupplyMaxVoltageName,
      static_cast<int>(round(power_status_.line_power_max_voltage)),
      kPowerSupplyMaxVoltageMax);
  ExpectEnumMetric(
      kPowerSupplyMaxPowerName,
      static_cast<int>(round(power_status_.line_power_max_voltage *
                             power_status_.line_power_max_current)),
      kPowerSupplyMaxPowerMax);
  collector_.HandlePowerStatusUpdate(power_status_);

  // Nothing should be reported when line power is off.
  power_status_.line_power_on = false;
  collector_.HandlePowerStatusUpdate(power_status_);
}

TEST_F(MetricsCollectorTest, PowerSupplyType) {
  metrics_to_test_ = {kPowerSupplyTypeName};
  IgnoreHandlePowerStatusUpdateMetrics();
  power_status_.line_power_on = false;
  Init();

  power_status_.line_power_on = true;
  power_status_.line_power_type = system::PowerSupply::kUsbPdType;
  ExpectEnumMetric(kPowerSupplyTypeName,
                   static_cast<int>(PowerSupplyType::USB_PD),
                   static_cast<int>(PowerSupplyType::MAX));
  collector_.HandlePowerStatusUpdate(power_status_);

  power_status_.line_power_type = system::PowerSupply::kBrickIdType;
  ExpectEnumMetric(kPowerSupplyTypeName,
                   static_cast<int>(PowerSupplyType::BRICK_ID),
                   static_cast<int>(PowerSupplyType::MAX));
  collector_.HandlePowerStatusUpdate(power_status_);

  power_status_.line_power_type = "BOGUS";
  ExpectEnumMetric(kPowerSupplyTypeName,
                   static_cast<int>(PowerSupplyType::OTHER),
                   static_cast<int>(PowerSupplyType::MAX));
  collector_.HandlePowerStatusUpdate(power_status_);

  // Nothing should be reported when line power is off.
  power_status_.line_power_on = false;
  collector_.HandlePowerStatusUpdate(power_status_);
}

TEST_F(MetricsCollectorTest, ConnectedChargingPorts) {
  metrics_to_test_ = {kConnectedChargingPortsName};
  IgnoreHandlePowerStatusUpdateMetrics();
  Init();

  // Start out without any ports.
  ExpectEnumMetric(kConnectedChargingPortsName,
                   static_cast<int>(ConnectedChargingPorts::NONE),
                   static_cast<int>(ConnectedChargingPorts::MAX));
  collector_.HandlePowerStatusUpdate(power_status_);

  // Add a single disconnected port.
  power_status_.ports.emplace_back();
  ExpectEnumMetric(kConnectedChargingPortsName,
                   static_cast<int>(ConnectedChargingPorts::NONE),
                   static_cast<int>(ConnectedChargingPorts::MAX));
  collector_.HandlePowerStatusUpdate(power_status_);

  // Connect the port to a dedicated charger.
  power_status_.ports[0].role =
      system::PowerStatus::Port::Role::DEDICATED_SOURCE;
  ExpectEnumMetric(kConnectedChargingPortsName,
                   static_cast<int>(ConnectedChargingPorts::PORT1),
                   static_cast<int>(ConnectedChargingPorts::MAX));
  collector_.HandlePowerStatusUpdate(power_status_);

  // Add a second disconnected port.
  power_status_.ports.emplace_back();
  ExpectEnumMetric(kConnectedChargingPortsName,
                   static_cast<int>(ConnectedChargingPorts::PORT1),
                   static_cast<int>(ConnectedChargingPorts::MAX));
  collector_.HandlePowerStatusUpdate(power_status_);

  // Connect the second port to a dual-role device.
  power_status_.ports[1].role = system::PowerStatus::Port::Role::DUAL_ROLE;
  ExpectEnumMetric(kConnectedChargingPortsName,
                   static_cast<int>(ConnectedChargingPorts::PORT1_PORT2),
                   static_cast<int>(ConnectedChargingPorts::MAX));
  collector_.HandlePowerStatusUpdate(power_status_);

  // Disconnect the first port.
  power_status_.ports[0].role = system::PowerStatus::Port::Role::NONE;
  ExpectEnumMetric(kConnectedChargingPortsName,
                   static_cast<int>(ConnectedChargingPorts::PORT2),
                   static_cast<int>(ConnectedChargingPorts::MAX));
  collector_.HandlePowerStatusUpdate(power_status_);

  // Add a third port, which this code doesn't support.
  power_status_.ports.emplace_back();
  ExpectEnumMetric(kConnectedChargingPortsName,
                   static_cast<int>(ConnectedChargingPorts::TOO_MANY_PORTS),
                   static_cast<int>(ConnectedChargingPorts::MAX));
  collector_.HandlePowerStatusUpdate(power_status_);
}

TEST_F(MetricsCollectorTest, TestBatteryMetricsAtBootOnBattery) {
  ExpectEnumMetric(MetricsCollector::AppendPowerSourceToEnumName(
                       kBatteryRemainingAtBootName, PowerSource::BATTERY),
                   power_status_.battery_percentage, kMaxPercent);
  first_run_after_boot_ = true;
  Init();
}

TEST_F(MetricsCollectorTest, TestBatteryMetricsAtBootOnAC) {
  power_status_.line_power_on = true;
  ExpectEnumMetric(MetricsCollector::AppendPowerSourceToEnumName(
                       kBatteryRemainingAtBootName, PowerSource::AC),
                   power_status_.battery_percentage, kMaxPercent);
  first_run_after_boot_ = true;
  Init();
}

TEST_F(MetricsCollectorTest, DimEventMetricsAC) {
  power_status_.line_power_on = true;
  Init();
  ExpectEnumMetric(
      MetricsCollector::AppendPowerSourceToEnumName(kDimEvent, PowerSource::AC),
      static_cast<int>(DimEvent::STANDARD_DIM),
      static_cast<int>(DimEvent::MAX));
  collector_.GenerateDimEventMetrics(DimEvent::STANDARD_DIM);
}

TEST_F(MetricsCollectorTest, DimEventMetricsBattery) {
  power_status_.line_power_on = false;
  Init();
  ExpectEnumMetric(MetricsCollector::AppendPowerSourceToEnumName(
                       kDimEvent, PowerSource::BATTERY),
                   static_cast<int>(DimEvent::QUICK_DIM_REVERTED_BY_HPS),
                   static_cast<int>(DimEvent::MAX));
  collector_.GenerateDimEventMetrics(DimEvent::QUICK_DIM_REVERTED_BY_HPS);
}

TEST_F(MetricsCollectorTest, GenerateHpsEventDurationMetrics) {
  Init();
  ExpectMetric(kQuickDimDurationBeforeRevertedByHpsSec, 13, 1, 3600, 50);
  collector_.GenerateHpsEventDurationMetrics(
      kQuickDimDurationBeforeRevertedByHpsSec, base::Seconds(13));
}

TEST_F(MetricsCollectorTest, LockEventMetricsAC) {
  power_status_.line_power_on = true;
  Init();
  ExpectEnumMetric(MetricsCollector::AppendPowerSourceToEnumName(
                       kLockEvent, PowerSource::AC),
                   static_cast<int>(LockEvent::STANDARD_LOCK),
                   static_cast<int>(LockEvent::MAX));
  collector_.GenerateLockEventMetrics(LockEvent::STANDARD_LOCK);
}

TEST_F(MetricsCollectorTest, LockEventMetricsBattery) {
  power_status_.line_power_on = false;
  Init();
  ExpectEnumMetric(MetricsCollector::AppendPowerSourceToEnumName(
                       kLockEvent, PowerSource::BATTERY),
                   static_cast<int>(LockEvent::QUICK_LOCK),
                   static_cast<int>(LockEvent::MAX));
  collector_.GenerateLockEventMetrics(LockEvent::QUICK_LOCK);
}

class AdaptiveChargingMetricsTest : public TestEnvironment {
 public:
  AdaptiveChargingMetricsTest() : metrics_sender_(metrics_) {}

 protected:
  void Init() {
    collector_.clock_.set_current_time_for_testing(base::TimeTicks() +
                                                   base::Microseconds(1000));
    collector_.clock_.set_current_boot_time_for_testing(
        base::TimeTicks() + base::Microseconds(2000));
    collector_.Init(&prefs_, &display_backlight_controller_,
                    &keyboard_backlight_controller_, {},
                    /*first_run_after_boot=*/false);
  }

  base::TimeTicks GetCurrentBootTime() {
    return collector_.clock_.GetCurrentBootTime();
  }

  FakePrefs prefs_;
  policy::BacklightControllerStub display_backlight_controller_;
  policy::BacklightControllerStub keyboard_backlight_controller_;

  FakeMetricsLibrary metrics_;
  MetricsSender metrics_sender_;
  MetricsCollector collector_;
};

TEST_F(AdaptiveChargingMetricsTest,
       AdaptiveChargingUnplugMetricsInActiveState) {
  Init();

  // Generate metrics where `target_time` is in the past.
  base::TimeTicks now = GetCurrentBootTime();
  collector_.GenerateAdaptiveChargingUnplugMetrics(
      AdaptiveChargingState::ACTIVE,
      /*target_time=*/now - base::Hours(1),
      /*hold_start_time=*/now - base::Hours(5),
      /*hold_end_time=*/now - base::Hours(3),
      /*charge_finished_time=*/now - base::Minutes(50),
      /*time_spent_slow_charging=*/base::Minutes(130),
      /*display_battery_percent=*/100.0);

  // Confirm metrics.
  struct Expected {
    std::string name;
    int value;
  };
  std::vector<Expected> expected = {
      {"Power.AdaptiveChargingMinutesDelta.Active.Early", 60},
      {"Power.AdaptiveChargingBatteryPercentageOnUnplug.SlowCharging", 100},
      {"Power.AdaptiveChargingMinutesToFull.SlowCharging", 130},
      {"Power.AdaptiveChargingMinutes.Delay", 120},
      {"Power.AdaptiveChargingMinutes.Available", 300},
      {"Power.AdaptiveChargingDelayDelta.Active.Early", 0},
      {"power.AdaptiveChargingMinutesFullOnAC.Active", 50},
  };
  for (const Expected& expected : expected) {
    EXPECT_EQ(metrics_.GetLast(expected.name), expected.value)
        << "Metric " << expected.name << "has unexpected value.";
  }
}

// Test metrics when `target_time` is in the future.
TEST_F(AdaptiveChargingMetricsTest,
       AdaptiveChargingUnplugMetricsTargetInFuture) {
  Init();

  // Generate metrics where `target_time` is in the future, and we switch
  // from slow charging to fast charging mid way.
  base::TimeTicks now = GetCurrentBootTime();
  collector_.GenerateAdaptiveChargingUnplugMetrics(
      AdaptiveChargingState::ACTIVE,
      /*target_time=*/now + base::Hours(1),
      /*hold_start_time=*/now - base::Hours(5),
      /*hold_end_time=*/now - base::Hours(3),
      /*charge_finished_time=*/now - base::Minutes(50),
      /*time_spent_slow_charging=*/base::Minutes(30),
      /*display_battery_percent=*/95.0);

  // Confirm metrics.
  struct Expected {
    std::string name;
    int value;
  };
  std::vector<Expected> expected = {
      {"Power.AdaptiveChargingMinutesDelta.Active.Late", 60},
      {"Power.AdaptiveChargingBatteryPercentageOnUnplug.MixedCharging", 95},
      {"Power.AdaptiveChargingMinutesToFull.MixedCharging", 130},
      {"Power.AdaptiveChargingMinutes.Delay", 120},
      {"Power.AdaptiveChargingMinutes.Available", 300},
      {"Power.AdaptiveChargingDelayDelta.Active.Early", 0},
      {"power.AdaptiveChargingMinutesFullOnAC.Active", 50},
  };
  for (const Expected& expected : expected) {
    EXPECT_EQ(metrics_.GetLast(expected.name), expected.value)
        << "Metric " << expected.name << " has unexpected value.";
  }
}

// Ensure metrics are recorded for every state.
TEST_F(AdaptiveChargingMetricsTest, AdaptiveChargingUnplugMetricsAllStates) {
  Init();

  // For each state, send out metrics, and ensure we see the state-specific
  // metric names we expected.
  struct Test {
    AdaptiveChargingState state;
    std::string name;
  };
  for (const Test& test : std::vector<Test>{
           Test{AdaptiveChargingState::ACTIVE, "Active"},
           Test{AdaptiveChargingState::INACTIVE, "Active"},    // same as ACTIVE
           Test{AdaptiveChargingState::SLOWCHARGE, "Active"},  // same as ACTIVE
           Test{AdaptiveChargingState::HEURISTIC_DISABLED, "HeuristicDisabled"},
           Test{AdaptiveChargingState::USER_CANCELED, "UserCanceled"},
           Test{AdaptiveChargingState::USER_DISABLED, "UserDisabled"},
           Test{AdaptiveChargingState::SHUTDOWN, "Shutdown"},
           Test{AdaptiveChargingState::NOT_SUPPORTED, "NotSupported"},
       }) {
    metrics_.Clear();

    base::TimeTicks now = GetCurrentBootTime();
    collector_.GenerateAdaptiveChargingUnplugMetrics(
        test.state,
        /*target_time=*/now - base::Hours(1),
        /*hold_start_time=*/now - base::Hours(5),
        /*hold_end_time=*/now - base::Hours(3),
        /*charge_finished_time=*/now - base::Minutes(50),
        /*time_spent_slow_charging=*/base::Minutes(130),
        /*display_battery_percent=*/100.0);

    EXPECT_EQ(metrics_.NumCalls("Power.AdaptiveChargingMinutesDelta." +
                                test.name + ".Early"),
              1);
    EXPECT_EQ(metrics_.NumCalls("Power.AdaptiveChargingDelayDelta." +
                                test.name + ".Early"),
              1);
  }
}

class MockResidencyReader : public ResidencyReader {
 public:
  MockResidencyReader() = default;
  ~MockResidencyReader() override = default;

  MOCK_METHOD(base::TimeDelta, ReadResidency, (), (override));
};

// Base class for idle state residency tracker tests.
class IdleResidencyTrackerTest : public TestEnvironment {
 public:
  IdleResidencyTrackerTest() = default;

 protected:
  // Initializes |tracker_| with a newly created |reader_mock_|.
  void SetUp() override {
    reader_mock_ = std::make_shared<MockResidencyReader>();
    tracker_ = IdleResidencyTracker(reader_mock_);
  }

  void TearDown() override {
    // Note: Given RAII this is excessive but follows SetUp semantics.
    tracker_ = {};
    reader_mock_.reset();
  }

  std::shared_ptr<MockResidencyReader> reader_mock_;
  IdleResidencyTracker tracker_;
};

// Test that InvalidValue is returned on an empty path.
TEST_F(IdleResidencyTrackerTest, SingleValueResidencyReaderEmptyPath) {
  SingleValueResidencyReader reader(base::FilePath(""));
  ASSERT_EQ(reader.ReadResidency(), ResidencyReader::InvalidValue);
}

// Test that InvalidValue is returned on an invalid path.
TEST_F(IdleResidencyTrackerTest, SingleValueResidencyReaderInvalidPath) {
  SingleValueResidencyReader reader(base::FilePath("this_does_not_exists"));
  ASSERT_EQ(reader.ReadResidency(), ResidencyReader::InvalidValue);
}

// Test that integer is read successfully from a valid path with a valid value.
TEST_F(IdleResidencyTrackerTest, SingleValueResidencyReaderValidValue) {
  static const char* file_name = "some_file";
  const base::TimeDelta exp_value = base::Microseconds(10);
  base::ScopedTempDir temp_root;
  CHECK(temp_root.CreateUniqueTempDir());
  base::FilePath path = temp_root.GetPath().Append(file_name);
  // Create all required parent directories.
  CHECK(base::CreateDirectory(path.DirName()));
  // Create a file for SingleValueResidencyReader to pick up.
  std::string buf = base::NumberToString(exp_value.InMicroseconds());
  ASSERT_EQ(base::WriteFile(path, buf.data(), buf.size()), buf.size());
  SingleValueResidencyReader reader(path);
  ASSERT_EQ(reader.ReadResidency(), exp_value);
  // Clean up.
  CHECK(temp_root.Delete());
}

// Test that InvalidValue returned from a valid path with an invalid value.
TEST_F(IdleResidencyTrackerTest, SingleValueResidencyReaderInvalidValue) {
  static const char* file_name = "some_file";
  base::ScopedTempDir temp_root;
  CHECK(temp_root.CreateUniqueTempDir());
  base::FilePath path = temp_root.GetPath().Append(file_name);
  // Create all required parent directories.
  CHECK(base::CreateDirectory(path.DirName()));
  // Create a file for SingleValueResidencyReader to pick up.
  std::string buf = "this_is_not_a_number";
  ASSERT_EQ(base::WriteFile(path, buf.data(), buf.size()), buf.size());
  SingleValueResidencyReader reader(path);
  ASSERT_EQ(reader.ReadResidency(), ResidencyReader::InvalidValue);
  // Clean up.
  CHECK(temp_root.Delete());
}

// Test that IsValid is false when ResidencyReader has an empty path (so will
// always return InvalidValue).
TEST_F(IdleResidencyTrackerTest, IdleResidencyTrackerEmptyPathReader) {
  // First check that a freshly initialized IdleResidencyTracker returns
  // invalid values.
  ASSERT_FALSE(tracker_.IsValid());
  ASSERT_EQ(tracker_.PreSuspend(), ResidencyReader::InvalidValue);
  ASSERT_EQ(tracker_.PostResume(), ResidencyReader::InvalidValue);
  // Prime the mock to simulate empty/invalid path.
  EXPECT_CALL(*reader_mock_, ReadResidency())
      .Times(1)
      .WillOnce(Return(ResidencyReader::InvalidValue))
      .RetiresOnSaturation();
  tracker_.UpdatePreSuspend();
  // Check that IsValid() and PreSuspend() are reported correctly.
  ASSERT_FALSE(tracker_.IsValid());
  ASSERT_EQ(tracker_.PreSuspend(), ResidencyReader::InvalidValue);
  // Prime the mock to simulate empty/invalid path.
  EXPECT_CALL(*reader_mock_, ReadResidency())
      .Times(1)
      .WillOnce(Return(ResidencyReader::InvalidValue))
      .RetiresOnSaturation();
  tracker_.UpdatePostResume();
  // Check that IsValid() and PostResume() are reported correctly.
  ASSERT_FALSE(tracker_.IsValid());
  ASSERT_EQ(tracker_.PostResume(), ResidencyReader::InvalidValue);
  // |metrics_lib_| is strict mock. Unexpected method call will fail this test.
  Mock::VerifyAndClearExpectations(reader_mock_.get());
}

// Test that appropriate values are updated on Update*() calls.
TEST_F(IdleResidencyTrackerTest, IdleResidencyTrackerValidUpdates) {
  const auto pre_suspend_exp_val = base::Microseconds(10);
  const auto post_resume_exp_val = base::Microseconds(33);
  // First check that a freshly initialized IdleResidencyTracker returns
  // invalid values.
  ASSERT_FALSE(tracker_.IsValid());
  ASSERT_EQ(tracker_.PreSuspend(), ResidencyReader::InvalidValue);
  ASSERT_EQ(tracker_.PostResume(), ResidencyReader::InvalidValue);
  // Prime the mock for UpdatePreSuspend().
  EXPECT_CALL(*reader_mock_, ReadResidency())
      .Times(1)
      .WillOnce(Return(pre_suspend_exp_val))
      .RetiresOnSaturation();
  tracker_.UpdatePreSuspend();
  // With only pre-suspend sample tracker is not valid.
  ASSERT_FALSE(tracker_.IsValid());
  ASSERT_EQ(tracker_.PreSuspend(), pre_suspend_exp_val);
  ASSERT_EQ(tracker_.PostResume(), ResidencyReader::InvalidValue);
  // Prime the mock for UpdatePostResume().
  EXPECT_CALL(*reader_mock_, ReadResidency())
      .Times(1)
      .WillOnce(Return(post_resume_exp_val))
      .RetiresOnSaturation();
  tracker_.UpdatePostResume();
  // Both samples in so tracker is valid.
  ASSERT_TRUE(tracker_.IsValid());
  ASSERT_EQ(tracker_.PreSuspend(), pre_suspend_exp_val);
  ASSERT_EQ(tracker_.PostResume(), post_resume_exp_val);
  // Prime the mock for an invalid residency value to check IsValid() flipping.
  EXPECT_CALL(*reader_mock_, ReadResidency())
      .Times(1)
      .WillOnce(Return(ResidencyReader::InvalidValue))
      .RetiresOnSaturation();
  tracker_.UpdatePostResume();
  // Post-resume is invalid so tracker should be invalid and pre-suspend should
  // not update.
  ASSERT_FALSE(tracker_.IsValid());
  ASSERT_EQ(tracker_.PreSuspend(), pre_suspend_exp_val);
  ASSERT_EQ(tracker_.PostResume(), ResidencyReader::InvalidValue);
  // |metrics_lib_| is strict mock. Unexpected method call will fail this test.
  Mock::VerifyAndClearExpectations(reader_mock_.get());
}

// Base class for idle state (i.e. S0ix) residency rate related tests.
class IdleStateResidencyMetricsTest : public MetricsCollectorTest {
 public:
  IdleStateResidencyMetricsTest() = default;

 protected:
  enum class S0ixResidencyFileType {
    BIG_CORE,
    SMALL_CORE,
    NONE,
  };

  struct Residency {
    base::FilePath path_;
    base::TimeDelta before_suspend_;
    base::TimeDelta before_resume_;
  };

  // Creates idle state residency files (if needed) rooted in |temp_root_dir_|.
  // S0ix file type is determined by |residency_file_type|, PC10 file is created
  // if |pc10_residency_file_present| is true.
  // Also sets |kSuspendToIdlePref| pref to |suspend_to_idle| and initializes
  // |collector_|.
  void Init(S0ixResidencyFileType residency_file_type,
            bool suspend_to_idle = true,
            bool pc10_residency_file_present = true) {
    if (suspend_to_idle)
      prefs_.SetInt64(kSuspendToIdlePref, 1);

    if (residency_file_type == S0ixResidencyFileType::BIG_CORE) {
      residencies_[IdleState::S0ix].path_ =
          GetPath(base::FilePath(MetricsCollector::kBigCoreS0ixResidencyPath));
    } else if (residency_file_type == S0ixResidencyFileType::SMALL_CORE) {
      residencies_[IdleState::S0ix].path_ = GetPath(
          base::FilePath(MetricsCollector::kSmallCoreS0ixResidencyPath));
    }

    if (pc10_residency_file_present) {
      residencies_[IdleState::PC10].path_ =
          GetPath(base::FilePath(MetricsCollector::kAcpiPC10ResidencyPath));
    }

    for (const auto& residency : residencies_) {
      if (!residency.path_.empty()) {
        // Create all required parent directories.
        CHECK(base::CreateDirectory(residency.path_.DirName()));
        // Create empty file.
        CHECK_EQ(base::WriteFile(residency.path_, "", 0), 0);
      }
    }

    MetricsCollectorTest::Init();
  }

  // Does suspend and resume. Also writes residency to |residency_path_| (if not
  // empty) before and after suspend.
  void SuspendAndResume() {
    for (const auto& residency : residencies_) {
      if (!residency.path_.empty())
        WriteResidency(residency, residency.before_suspend_);
    }

    collector_.PrepareForSuspend();
    AdvanceTime(suspend_duration_);
    // Adds expectations to ignore |kSuspendAttemptsBeforeSuccessName| metric
    // sent by HandleResume().
    IgnoreMetric(kSuspendAttemptsBeforeSuccessName);

    for (const auto& residency : residencies_) {
      if (!residency.path_.empty())
        WriteResidency(residency, residency.before_resume_);
    }

    collector_.HandleResume(1, false);
  }

  // Expect |kS0ixResidencyRateName| enum metric will be generated.
  void ExpectS2IdleResidencyRateMetricCall() {
    const Residency& s0ix = residencies_[IdleState::S0ix];
    int expected_s0ix_percentage =
        MetricsCollector::GetExpectedResidencyPercent(
            suspend_duration_, s0ix.before_resume_ - s0ix.before_suspend_);
    ExpectEnumMetric(kS0ixResidencyRateName, expected_s0ix_percentage,
                     kMaxPercent);
  }

  // Expect |kPC10RuntimeResidencyRateName| and
  // |kPC10inS0ixRuntimeResidencyRateName| enum metrics will be
  // generated.
  void ExpectRuntimeResidencyRateMetricCall(int expected_pc10_percentage,
                                            int expected_s0ix_percentage,
                                            const bool expect_s0ix = true) {
    ExpectEnumMetric(kPC10RuntimeResidencyRateName, expected_pc10_percentage,
                     kMaxPercent);
    if (expect_s0ix)
      ExpectEnumMetric(kPC10inS0ixRuntimeResidencyRateName,
                       expected_s0ix_percentage, kMaxPercent);
  }

  // Writes |residency| to |residency_path_|.
  void WriteResidency(const Residency& residency,
                      const base::TimeDelta& value) {
    std::string buf = base::NumberToString(
        static_cast<uint64_t>(llabs(value.InMicroseconds())));
    ASSERT_EQ(base::WriteFile(residency.path_, buf.data(), buf.size()),
              buf.size());
  }

  Residency residencies_[IdleState::COUNT] = {
      [IdleState::S0ix] = {.before_suspend_ = base::Minutes(50),
                           .before_resume_ = base::Minutes(100)},
      [IdleState::PC10] = {.before_suspend_ = base::Minutes(50),
                           .before_resume_ = base::Minutes(100)},
  };
  base::TimeDelta suspend_duration_ = base::Hours(1);
};

// Test expected residency calculation for valid values.
TEST_F(IdleStateResidencyMetricsTest, GetExpectedResidencyPercentValid) {
  // Check non-zero overhead.
  int residency_percent = collector_.GetExpectedResidencyPercent(
      base::Minutes(3), base::Minutes(1), base::Minutes(1));
  ASSERT_EQ(residency_percent, 50);
  // Check zero overhead.
  residency_percent = collector_.GetExpectedResidencyPercent(
      base::Minutes(3), base::Minutes(1), base::Minutes(0));
  ASSERT_EQ(residency_percent, 33);
}

// Test expected residency calculation returns 0 on reference <= overhead.
TEST_F(IdleStateResidencyMetricsTest, GetExpectedResidencyPercentInvalid) {
  // Check reference < overhead.
  int residency_percent = collector_.GetExpectedResidencyPercent(
      base::Minutes(1), base::Minutes(1), base::Minutes(2));
  ASSERT_EQ(residency_percent, 0);
  // Check reference == overhead.
  residency_percent = collector_.GetExpectedResidencyPercent(
      base::Minutes(2), base::Minutes(1), base::Minutes(2));
  ASSERT_EQ(residency_percent, 0);
  // Check reference == overhead == 0.
  residency_percent = collector_.GetExpectedResidencyPercent(
      base::Minutes(0), base::Minutes(1), base::Minutes(0));
  ASSERT_EQ(residency_percent, 0);
}

// Test S0ix UMA metrics are not reported when residency files do not exist.
TEST_F(IdleStateResidencyMetricsTest, S0ixResidencyMetricsNoResidencyFiles) {
  suspend_duration_ = base::Hours(1);
  Init(S0ixResidencyFileType::NONE);
  SuspendAndResume();
  // |metrics_lib_| is strict mock. Unexpected method call will fail this test.
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

// Test S0ix UMA metrics are reported when |kSmallCoreS0ixResidencyPath| exist.
TEST_F(IdleStateResidencyMetricsTest, SmallCorePathExist) {
  Init(S0ixResidencyFileType::SMALL_CORE);
  ExpectS2IdleResidencyRateMetricCall();
  SuspendAndResume();
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

// Test S0ix UMA metrics are reported when |kBigCoreS0ixResidencyPath| exist.
TEST_F(IdleStateResidencyMetricsTest, BigCorePathExist) {
  Init(S0ixResidencyFileType::BIG_CORE);
  ExpectS2IdleResidencyRateMetricCall();
  SuspendAndResume();
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

// Test S0ix UMA metrics are not reported when suspend to idle is not enabled.
TEST_F(IdleStateResidencyMetricsTest, S0ixResidencyMetricsS0ixNotEnabled) {
  Init(S0ixResidencyFileType::SMALL_CORE, false /*suspend_to_idle*/);
  SuspendAndResume();
  // |metrics_lib_| is strict mock. Unexpected method call will fail this test.
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

// Test metrics are not reported when device suspends less than
// |KS0ixOverheadTime|.
TEST_F(IdleStateResidencyMetricsTest, ShortSuspend) {
  suspend_duration_ = MetricsCollector::KS0ixOverheadTime - base::Seconds(1);
  Init(S0ixResidencyFileType::SMALL_CORE);
  SuspendAndResume();
  // |metrics_lib_| is strict mock. Unexpected method call will fail this test.
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

// Test metrics are not reported when the residency counter overflows.
TEST_F(IdleStateResidencyMetricsTest, ResidencyCounterOverflow) {
  Residency& s0ix = residencies_[IdleState::S0ix];
  s0ix.before_resume_ = s0ix.before_suspend_ - base::Minutes(1);
  Init(S0ixResidencyFileType::SMALL_CORE);
  SuspendAndResume();
  // |metrics_lib_| is strict mock. Unexpected method call will fail this test.
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

// Test metrics are not reported when suspend time is more than max residency.
TEST_F(IdleStateResidencyMetricsTest, SuspendTimeMoreThanMaxResidency) {
  suspend_duration_ = base::Microseconds(100 * (int64_t)UINT32_MAX + 1);
  Init(S0ixResidencyFileType::BIG_CORE);
  SuspendAndResume();
  // |metrics_lib_| is strict Mock. Unexpected method call will fail this test.
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

// NOTE: The testing scenario for runtime idle state residency always involves
// two suspend/resume cycles. The reason for this is to mimic the real-world
// case, where HandleSuspend() only reports runtime metrics if a previous read
// of PC10 and S0ix residency counters was successful. That may only happen in
// HandleSuspend() which won't be called upon initial boot.

// Test metrics are not reported without S0ix residency file.
TEST_F(IdleStateResidencyMetricsTest, NoS0ixFileButPC10FileExists) {
  Init(S0ixResidencyFileType::NONE);
  SuspendAndResume();
  SuspendAndResume();
  // |metrics_lib_| is strict Mock. Unexpected method call will fail this test.
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

// Test runtime metrics are not reported without PC10 residency file.
TEST_F(IdleStateResidencyMetricsTest, NoPC10ResidencyFile) {
  Init(S0ixResidencyFileType::BIG_CORE, true,
       false /*pc10_residency_file_present*/);
  ExpectS2IdleResidencyRateMetricCall();
  SuspendAndResume();
  ExpectS2IdleResidencyRateMetricCall();
  SuspendAndResume();
  // |metrics_lib_| is strict Mock. Unexpected method call will fail this test.
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

// Test runtime metrics are reported when residency files exist.
TEST_F(IdleStateResidencyMetricsTest, PC10ResidencyFileExists) {
  const base::TimeDelta runtime_duration = base::Hours(1);
  Residency& pc10 = residencies_[IdleState::PC10];
  Residency& s0ix = residencies_[IdleState::S0ix];

  Init(S0ixResidencyFileType::BIG_CORE);
  ExpectS2IdleResidencyRateMetricCall();
  SuspendAndResume();
  AdvanceTime(runtime_duration);
  // Device is suspending so increase runtime counters so that S0ix in PC10
  // and PC10 residencies are at 50%.
  pc10.before_suspend_ = pc10.before_resume_ + runtime_duration / 2;
  s0ix.before_suspend_ = s0ix.before_resume_ + runtime_duration / 4;
  ExpectRuntimeResidencyRateMetricCall(50, 50);
  // Once runtime expects are prepared, update residencies for post-suspend.
  pc10.before_resume_ = pc10.before_suspend_ + base::Minutes(10);
  s0ix.before_resume_ = s0ix.before_suspend_ + base::Minutes(5);
  ExpectS2IdleResidencyRateMetricCall();
  SuspendAndResume();
  // |metrics_lib_| is strict Mock. Unexpected method call will fail this test.
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

// Test runtime metrics are reported even when suspend to idle is not enabled.
TEST_F(IdleStateResidencyMetricsTest, NoS2IdleReporting) {
  const base::TimeDelta runtime_duration = base::Hours(1);
  Residency& pc10 = residencies_[IdleState::PC10];
  Residency& s0ix = residencies_[IdleState::S0ix];

  Init(S0ixResidencyFileType::BIG_CORE, false /*suspend_to_idle*/);
  SuspendAndResume();
  AdvanceTime(runtime_duration);
  // Device is suspending so increase runtime counters so that S0ix in PC10
  // and PC10 residencies are at 50%.
  pc10.before_suspend_ = pc10.before_resume_ + runtime_duration / 2;
  s0ix.before_suspend_ = s0ix.before_resume_ + runtime_duration / 4;
  ExpectRuntimeResidencyRateMetricCall(50, 50);
  // Once runtime expects are prepared, update residencies for post-suspend.
  pc10.before_resume_ = pc10.before_suspend_ + base::Minutes(10);
  s0ix.before_resume_ = s0ix.before_suspend_ + base::Minutes(5);
  SuspendAndResume();
  // |metrics_lib_| is strict Mock. Unexpected method call will fail this test.
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

// Test runtime metrics are not reported when the PC10 residency counter
// overflows.
TEST_F(IdleStateResidencyMetricsTest, RuntimePC10CounterOverflow) {
  const base::TimeDelta runtime_duration = base::Hours(1);
  Residency& pc10 = residencies_[IdleState::PC10];
  Residency& s0ix = residencies_[IdleState::S0ix];

  Init(S0ixResidencyFileType::BIG_CORE);
  ExpectS2IdleResidencyRateMetricCall();
  SuspendAndResume();
  AdvanceTime(runtime_duration);
  // PC10 counter overflows in runtime, S0ix doesn't. Expect no runtime report.
  pc10.before_suspend_ = pc10.before_resume_ - base::Minutes(1);
  s0ix.before_suspend_ = s0ix.before_resume_ + runtime_duration / 4;
  s0ix.before_resume_ = s0ix.before_suspend_ + base::Minutes(5);
  ExpectS2IdleResidencyRateMetricCall();
  SuspendAndResume();
  // |metrics_lib_| is strict Mock. Unexpected method call will fail this test.
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

// Test runtime metrics are not reported when the S0ix residency counter
// overflows.
TEST_F(IdleStateResidencyMetricsTest, RuntimeS0ixCounterOverflow) {
  const base::TimeDelta runtime_duration = base::Hours(1);
  Residency& pc10 = residencies_[IdleState::PC10];
  Residency& s0ix = residencies_[IdleState::S0ix];

  Init(S0ixResidencyFileType::BIG_CORE);
  ExpectS2IdleResidencyRateMetricCall();
  SuspendAndResume();
  AdvanceTime(runtime_duration);
  // S0ix counter overflows in runtime, PC10 doesn't. Expect no runtime report.
  pc10.before_suspend_ = pc10.before_resume_ + runtime_duration / 2;
  s0ix.before_suspend_ = s0ix.before_resume_ - base::Minutes(1);
  pc10.before_resume_ = pc10.before_suspend_ + base::Minutes(10);
  ExpectS2IdleResidencyRateMetricCall();
  SuspendAndResume();
  // |metrics_lib_| is strict Mock. Unexpected method call will fail this test.
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

// Test runtime metrics are not reported when suspend time is less than the
// overhead.
TEST_F(IdleStateResidencyMetricsTest, RuntimeLessThanOverhead) {
  const base::TimeDelta runtime_duration =
      MetricsCollector::kRuntimeS0ixOverheadTime / 2;
  Residency& pc10 = residencies_[IdleState::PC10];
  Residency& s0ix = residencies_[IdleState::S0ix];

  Init(S0ixResidencyFileType::BIG_CORE);
  ExpectS2IdleResidencyRateMetricCall();
  SuspendAndResume();
  AdvanceTime(runtime_duration);
  // Set counters to something reasonable.
  pc10.before_suspend_ = pc10.before_resume_ + base::Minutes(10);
  s0ix.before_suspend_ = s0ix.before_resume_ + base::Minutes(5);
  SuspendAndResume();
  // |metrics_lib_| is strict Mock. Unexpected method call will fail this test.
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

// Test overhead is taken into account in runtime metrics.
TEST_F(IdleStateResidencyMetricsTest, RuntimeMoreThanOverhead) {
  const base::TimeDelta runtime_duration =
      MetricsCollector::kRuntimeS0ixOverheadTime * 3;
  Residency& pc10 = residencies_[IdleState::PC10];
  Residency& s0ix = residencies_[IdleState::S0ix];

  Init(S0ixResidencyFileType::BIG_CORE);
  ExpectS2IdleResidencyRateMetricCall();
  SuspendAndResume();
  AdvanceTime(runtime_duration);
  // Set counters to something reasonable.
  pc10.before_suspend_ =
      pc10.before_resume_ + MetricsCollector::kRuntimeS0ixOverheadTime * 2;
  s0ix.before_suspend_ =
      s0ix.before_resume_ + MetricsCollector::kRuntimeS0ixOverheadTime * 1;
  // For PC10 residency, overhead is subtracted from expected runtime, hence
  // we get a 100% rate.
  // For PC10 in S0ix residency no overhead should be applied (we want to round
  // down). Hence it should be 50%.
  ExpectRuntimeResidencyRateMetricCall(100, 50);
  SuspendAndResume();
  // |metrics_lib_| is strict Mock. Unexpected method call will fail this test.
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

// Test runtime metrics are not reported when suspend time is more than max
// residency.
TEST_F(IdleStateResidencyMetricsTest, RuntimeMoreThanMaxResidency) {
  const base::TimeDelta runtime_duration =
      base::Microseconds(100 * (int64_t)UINT32_MAX + 1);
  Residency& pc10 = residencies_[IdleState::PC10];
  Residency& s0ix = residencies_[IdleState::S0ix];

  Init(S0ixResidencyFileType::BIG_CORE);
  ExpectS2IdleResidencyRateMetricCall();
  SuspendAndResume();
  AdvanceTime(runtime_duration);
  // Set counters to something reasonable.
  pc10.before_suspend_ = pc10.before_resume_ + base::Minutes(10);
  s0ix.before_suspend_ = s0ix.before_resume_ + base::Minutes(5);
  SuspendAndResume();
  // |metrics_lib_| is strict Mock. Unexpected method call will fail this test.
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

// Test runtime metrics are not reported for S0ix if PC10 residency is 0.
TEST_F(IdleStateResidencyMetricsTest, RuntimePC10Residency0) {
  const base::TimeDelta runtime_duration = base::Hours(1);
  Residency& pc10 = residencies_[IdleState::PC10];
  Residency& s0ix = residencies_[IdleState::S0ix];

  Init(S0ixResidencyFileType::BIG_CORE);
  ExpectS2IdleResidencyRateMetricCall();
  SuspendAndResume();
  AdvanceTime(runtime_duration);
  // PC10 didn't advance. Set S0ix to something sane though not reported.
  pc10.before_suspend_ = pc10.before_resume_;
  s0ix.before_suspend_ = s0ix.before_resume_ + runtime_duration / 2;
  ExpectRuntimeResidencyRateMetricCall(0, 0, false /*expect_s0ix*/);
  // Once runtime expects are prepared, update residencies for post-suspend.
  pc10.before_resume_ = pc10.before_suspend_ + base::Minutes(10);
  s0ix.before_resume_ = s0ix.before_suspend_ + base::Minutes(5);
  ExpectS2IdleResidencyRateMetricCall();
  SuspendAndResume();
  // |metrics_lib_| is strict Mock. Unexpected method call will fail this test.
  Mock::VerifyAndClearExpectations(&metrics_lib_);
}

}  // namespace power_manager::metrics
