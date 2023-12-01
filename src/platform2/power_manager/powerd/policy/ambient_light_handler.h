// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_AMBIENT_LIGHT_HANDLER_H_
#define POWER_MANAGER_POWERD_POLICY_AMBIENT_LIGHT_HANDLER_H_

#include <string>
#include <vector>

#include <base/compiler_specific.h>

#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/system/ambient_light_observer.h"
#include "power_manager/proto_bindings/backlight.pb.h"

namespace power_manager {

namespace system {
class AmbientLightSensorInterface;
}  // namespace system

namespace policy {

// Observes changes to ambient light reported by system::AmbientLightSensor
// and makes decisions about when backlight brightness should be adjusted.
class AmbientLightHandler : public system::AmbientLightObserver {
 public:
  enum class BrightnessChangeCause {
    AMBIENT_LIGHT = 0,
    EXTERNAL_POWER_CONNECTED,
    EXTERNAL_POWER_DISCONNECTED,
  };

  // Helper that converts an AmbientLightHandler::BrightnessChangeCause to the
  // corresponding Cause value for BacklightBrightnessChange protobufs.
  static BacklightBrightnessChange_Cause ToProtobufCause(
      BrightnessChangeCause als_cause);

  // Number of recent light sensor readings to include in log messages.
  // Public so it can be used in tests.
  static constexpr size_t kNumRecentReadingsToLog = 10;

  // Interface for classes that perform actions on behalf of
  // AmbientLightHandler.
  class Delegate {
   public:
    Delegate() = default;
    virtual ~Delegate() = default;

    // Invoked when the backlight brightness should be adjusted in response
    // to a change in ambient light.
    virtual void SetBrightnessPercentForAmbientLight(
        double brightness_percent, BrightnessChangeCause cause) = 0;

    // Invoked when the color temperature changes.
    virtual void OnColorTemperatureChanged(int color_temperature) = 0;

    // Invoked when ALS reading is taken after resume from suspension.
    virtual void ReportAmbientLightOnResumeMetrics(int lux) {}

    // Used to shortcut ALS calculations if they are not being used by Delegate.
    virtual bool IsUsingAmbientLight() const { return true; }
  };

  AmbientLightHandler(system::AmbientLightSensorInterface* sensor,
                      Delegate* delegate);
  AmbientLightHandler(const AmbientLightHandler&) = delete;
  AmbientLightHandler& operator=(const AmbientLightHandler&) = delete;

  ~AmbientLightHandler() override;

  void set_name(const std::string& name) { name_ = name; }

  // Initializes the object based on the data in |steps_pref_value|.
  // |lux_level_| is initialized to a synthetic value based on
  // |initial_brightness_percent|, the backlight brightness at the time of
  // initialization.
  //
  // |steps_pref_value| should contain one or more newline-separated brightness
  // steps, each containing three or four space-separated values:
  //
  //   <ac-backlight-percentage>
  //     <battery-backlight-percentage> (optional)
  //     <decrease-lux-threshold>
  //     <increase-lux-threshold>
  //
  // These values' meanings are described in more detail in BrightnessStep.
  //
  // Steps should be listed in ascending order when sorted by their thresholds,
  // and thresholds should overlap. For example, consider the following steps:
  //
  //    50.0   -1  100
  //    75.0   80  220
  //   100.0  200   -1
  //
  // A brightness level of 50% (corresponding to the bottom step) will be used
  // in conjunction with a starting ALS level of 25. After the ALS increases
  // above 100 (the bottom step's increase threshold), the brightness will
  // increase to 75% (the middle step), and after it increases above 220 (the
  // middle step's increase threshold), 100% (the top step) will be used. If the
  // ALS later falls below 200 (the top step's decrease threshold), 75% will be
  // used, and if it then falls below 80 (the middle step's decrease threshold),
  // 50% will be used.
  //
  // |smoothing_constant| should contain value in the range (0.0, 1.0] that will
  // be used to calculated |smoothed_lux_| using simple exponential smoothing.
  void Init(const std::string& steps_pref_value,
            double initial_brightness_percent,
            double smoothing_constant);

  // Should be called when the power source changes.
  void HandlePowerSourceChange(PowerSource source);

  // Should be called when resuming.
  void HandleResume();

  // Returns a string containing recent ALS readings, space-separated and
  // newest-to-oldest. Public so it can be called by tests.
  std::string GetRecentReadingsString() const;

  // system::AmbientLightObserver implementation:
  void OnAmbientLightUpdated(
      system::AmbientLightSensorInterface* sensor) override;

 private:
  // Contains information from prefs about a brightness step.
  struct BrightnessStep {
    // Backlight brightness in the range [0.0, 100.0] that corresponds to
    // this step.
    double ac_target_percent;
    double battery_target_percent;

    // If the lux level reported by |sensor_| drops below this value, a
    // lower step should be used.  -1 represents negative infinity.
    int decrease_lux_threshold;

    // If the lux level reported by |sensor_| increases above this value, a
    // higher step should be used.  -1 represents positive infinity.
    int increase_lux_threshold;
  };

  enum class HysteresisState {
    // The most-recent lux level matched |lux_level_|.
    STABLE,
    // The most-recent lux level was less than |lux_level_|.
    DECREASING,
    // The most-recent lux level was greater than |lux_level_|.
    INCREASING,
    // The brightness should be adjusted immediately after the next sensor
    // reading.
    IMMEDIATE,
    // Discard next sensor reading and go to |IMMEDIATE| state.
    RESUMING,
  };

  // Returns the current target backlight brightness percent based on
  // |step_index_| and |power_source_|.
  double GetTargetPercent() const;

  // Update |smoothed_lux_| using simple exponential smoothing.
  void UpdateSmoothedLux(int raw_lux);

  system::AmbientLightSensorInterface* sensor_;  // weak
  Delegate* delegate_;                           // weak

  PowerSource power_source_ = PowerSource::AC;

  // Rounded value of |smoothed_lux_| at the time of the last brightness
  // adjustment.
  int smoothed_lux_at_last_adjustment_ = 0;

  // Smoothed lux value from simple exponential smoothing.
  double smoothed_lux_ = 0.0;

  // Smoothing constant used to calculated smoothed ambient lux level, in the
  // range of (0.0, 1.0]. Value closer to 0.0 means |smoothed_lux_| will respond
  // to ambient light change slower. Value of 1.0 means smoothing is disabled.
  double smoothing_constant_ = 1.0;

  HysteresisState hysteresis_state_ = HysteresisState::IMMEDIATE;

  // If |hysteresis_state_| is DECREASING or INCREASING, number of readings
  // that have been received in the current state.
  int hysteresis_count_ = 0;

  // Brightness step data read from prefs. It is assumed that this data is
  // well-formed; specifically, for each entry in the file, the decrease
  // thresholds are monotonically increasing and the increase thresholds
  // are monotonically decreasing.
  std::vector<BrightnessStep> steps_;

  // Current brightness step within |steps_|.
  size_t step_index_ = 0;

  // Has |delegate_| been notified about an ambient-light-triggered change
  // yet?
  bool sent_initial_adjustment_ = false;

  // Human-readable name included in logging messages.  Useful for
  // distinguishing between different AmbientLightHandler instances.
  std::string name_;

  // Circular buffer containing recent readings from |sensor_| in
  // oldest-to-newest order (starting at |recent_lux_start_index_| and wrapping
  // around). Used for logging.
  std::vector<int> recent_lux_readings_;
  int recent_lux_start_index_ = 0;

  // Does the ambient light sensor need to report its next reading.
  bool report_on_resuming_ = false;
};

}  // namespace policy
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_POLICY_AMBIENT_LIGHT_HANDLER_H_
