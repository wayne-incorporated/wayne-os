// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/ambient_light_handler.h"

#include <cmath>
#include <limits>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>

#include "power_manager/powerd/system/ambient_light_sensor_interface.h"

namespace power_manager::policy {

namespace {

// Number of light sensor responses required to overcome temporal hysteresis.
const int kHysteresisThreshold = 2;

}  // namespace

// static
BacklightBrightnessChange_Cause AmbientLightHandler::ToProtobufCause(
    BrightnessChangeCause als_cause) {
  switch (als_cause) {
    case BrightnessChangeCause::AMBIENT_LIGHT:
      return BacklightBrightnessChange_Cause_AMBIENT_LIGHT_CHANGED;
    case BrightnessChangeCause::EXTERNAL_POWER_CONNECTED:
      return BacklightBrightnessChange_Cause_EXTERNAL_POWER_CONNECTED;
    case BrightnessChangeCause::EXTERNAL_POWER_DISCONNECTED:
      return BacklightBrightnessChange_Cause_EXTERNAL_POWER_DISCONNECTED;
  }
  NOTREACHED() << "Invalid cause " << static_cast<int>(als_cause);
  return BacklightBrightnessChange_Cause_AMBIENT_LIGHT_CHANGED;
}

constexpr size_t AmbientLightHandler::kNumRecentReadingsToLog;

AmbientLightHandler::AmbientLightHandler(
    system::AmbientLightSensorInterface* sensor, Delegate* delegate)
    : sensor_(sensor), delegate_(delegate) {
  DCHECK(sensor_);
  DCHECK(delegate_);
  recent_lux_readings_.reserve(kNumRecentReadingsToLog);
  sensor_->AddObserver(this);
}

AmbientLightHandler::~AmbientLightHandler() {
  sensor_->RemoveObserver(this);
}

void AmbientLightHandler::Init(const std::string& steps_pref_value,
                               double initial_brightness_percent,
                               double smoothing_constant) {
  std::vector<std::string> lines = base::SplitString(
      steps_pref_value, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  for (std::string& line : lines) {
    std::vector<std::string> segments = base::SplitString(
        line, " ", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
    BrightnessStep new_step;
    if (segments.size() == 3 &&
        base::StringToDouble(segments[0], &new_step.ac_target_percent) &&
        base::StringToInt(segments[1], &new_step.decrease_lux_threshold) &&
        base::StringToInt(segments[2], &new_step.increase_lux_threshold)) {
      new_step.battery_target_percent = new_step.ac_target_percent;
    } else if (segments.size() == 4 &&
               base::StringToDouble(segments[0], &new_step.ac_target_percent) &&
               base::StringToDouble(segments[1],
                                    &new_step.battery_target_percent) &&
               base::StringToInt(segments[2],
                                 &new_step.decrease_lux_threshold) &&
               base::StringToInt(segments[3],
                                 &new_step.increase_lux_threshold)) {
      // Okay, we've read all the fields.
    } else {
      LOG(FATAL) << "Steps pref has invalid line \"" << line << "\"";
    }
    steps_.push_back(new_step);
  }

  // The bottom and top steps should have infinite ranges to ensure that we
  // don't fall off either end.
  CHECK(!steps_.empty()) << "No brightness steps defined in pref";
  CHECK_EQ(steps_.front().decrease_lux_threshold, -1);
  CHECK_EQ(steps_.back().increase_lux_threshold, -1);

  // Start at the step nearest to the initial backlight level.
  double percent_delta = std::numeric_limits<double>::max();
  for (size_t i = 0; i < steps_.size(); i++) {
    double temp_delta =
        fabs(initial_brightness_percent - steps_[i].ac_target_percent);
    if (temp_delta < percent_delta) {
      percent_delta = temp_delta;
      step_index_ = i;
    }
  }
  CHECK_LT(step_index_, steps_.size());

  // Create a synthetic lux value that is in line with |step_index_|.
  // If one or both of the thresholds are unbounded, just do the best we
  // can.
  if (steps_[step_index_].decrease_lux_threshold >= 0 &&
      steps_[step_index_].increase_lux_threshold >= 0) {
    smoothed_lux_at_last_adjustment_ =
        steps_[step_index_].decrease_lux_threshold +
        (steps_[step_index_].increase_lux_threshold -
         steps_[step_index_].decrease_lux_threshold) /
            2;
  } else if (steps_[step_index_].decrease_lux_threshold >= 0) {
    smoothed_lux_at_last_adjustment_ =
        steps_[step_index_].decrease_lux_threshold;
  } else if (steps_[step_index_].increase_lux_threshold >= 0) {
    smoothed_lux_at_last_adjustment_ =
        steps_[step_index_].increase_lux_threshold;
  } else {
    smoothed_lux_at_last_adjustment_ = 0;
  }

  CHECK_GT(smoothing_constant, 0.0);
  CHECK_LE(smoothing_constant, 1.0);
  smoothing_constant_ = smoothing_constant;
}

void AmbientLightHandler::HandlePowerSourceChange(PowerSource source) {
  if (source == power_source_)
    return;

  double old_percent = GetTargetPercent();
  power_source_ = source;
  double new_percent = GetTargetPercent();
  if (new_percent != old_percent && sent_initial_adjustment_) {
    LOG(INFO) << "Going from " << old_percent << "% to " << new_percent
              << "% for power source change (" << name_ << ")";
    delegate_->SetBrightnessPercentForAmbientLight(
        new_percent, source == PowerSource::AC
                         ? BrightnessChangeCause::EXTERNAL_POWER_CONNECTED
                         : BrightnessChangeCause::EXTERNAL_POWER_DISCONNECTED);
  }
}

void AmbientLightHandler::HandleResume() {
  hysteresis_state_ = HysteresisState::RESUMING;
  report_on_resuming_ = true;
}

std::string AmbientLightHandler::GetRecentReadingsString() const {
  std::string str;
  for (int i = 0; i < recent_lux_readings_.size(); ++i) {
    const int index =
        (recent_lux_start_index_ - i - 1 + recent_lux_readings_.size()) %
        recent_lux_readings_.size();
    str += (i ? " " : "") + std::to_string(recent_lux_readings_[index]);
  }
  return str;
}

void AmbientLightHandler::OnAmbientLightUpdated(
    system::AmbientLightSensorInterface* sensor) {
  DCHECK_EQ(sensor, sensor_);

  // Discard first reading after resume as it is probably cached value.
  if (hysteresis_state_ == HysteresisState::RESUMING) {
    if (delegate_->IsUsingAmbientLight()) {
      hysteresis_state_ = HysteresisState::IMMEDIATE;
    } else {
      // Return to stable state if ALS is not being used by delegate
      hysteresis_state_ = HysteresisState::STABLE;
    }
    return;
  }

  const int raw_lux = sensor_->GetAmbientLightLux();
  if (raw_lux < 0) {
    LOG(WARNING) << "Sensor doesn't have valid value";
    return;
  }

  if (report_on_resuming_) {
    report_on_resuming_ = false;
    delegate_->ReportAmbientLightOnResumeMetrics(raw_lux);
  }

  // Currently we notify on every color temperature change.
  if (sensor_->IsColorSensor()) {
    const int color_temperature = sensor_->GetColorTemperature();
    if (color_temperature >= 0)
      delegate_->OnColorTemperatureChanged(color_temperature);
  }

  if (recent_lux_readings_.size() < kNumRecentReadingsToLog) {
    recent_lux_readings_.push_back(raw_lux);
  } else {
    // Overwrite the oldest value with the new reading.
    recent_lux_readings_[recent_lux_start_index_] = raw_lux;
    recent_lux_start_index_ =
        (recent_lux_start_index_ + 1) % recent_lux_readings_.size();
  }

  UpdateSmoothedLux(raw_lux);
  const int new_lux = lround(smoothed_lux_);

  if (hysteresis_state_ != HysteresisState::IMMEDIATE &&
      new_lux == smoothed_lux_at_last_adjustment_) {
    hysteresis_state_ = HysteresisState::STABLE;
    return;
  }

  int new_step_index = step_index_;
  int num_steps = steps_.size();
  if (new_lux > smoothed_lux_at_last_adjustment_) {
    if (hysteresis_state_ != HysteresisState::IMMEDIATE &&
        hysteresis_state_ != HysteresisState::INCREASING) {
      VLOG(1) << "ALS transitioned to brightness increasing (" << name_ << ")";
      hysteresis_state_ = HysteresisState::INCREASING;
      hysteresis_count_ = 0;
    }
    for (; new_step_index < num_steps; new_step_index++) {
      if (new_lux < steps_[new_step_index].increase_lux_threshold ||
          steps_[new_step_index].increase_lux_threshold == -1)
        break;
    }
  } else if (new_lux < smoothed_lux_at_last_adjustment_) {
    if (hysteresis_state_ != HysteresisState::IMMEDIATE &&
        hysteresis_state_ != HysteresisState::DECREASING) {
      VLOG(1) << "ALS transitioned to brightness decreasing (" << name_ << ")";
      hysteresis_state_ = HysteresisState::DECREASING;
      hysteresis_count_ = 0;
    }
    for (; new_step_index >= 0; new_step_index--) {
      if (new_lux > steps_[new_step_index].decrease_lux_threshold ||
          steps_[new_step_index].decrease_lux_threshold == -1)
        break;
    }
  }
  CHECK_GE(new_step_index, 0);
  CHECK_LT(new_step_index, num_steps);

  if (hysteresis_state_ == HysteresisState::IMMEDIATE) {
    step_index_ = new_step_index;
    double target_percent = GetTargetPercent();
    LOG(INFO) << "Immediately going to " << target_percent << "% (step "
              << step_index_ << ") for lux " << new_lux << " (" << name_ << ")";
    smoothed_lux_at_last_adjustment_ = new_lux;
    hysteresis_state_ = HysteresisState::STABLE;
    hysteresis_count_ = 0;
    delegate_->SetBrightnessPercentForAmbientLight(
        target_percent, BrightnessChangeCause::AMBIENT_LIGHT);
    sent_initial_adjustment_ = true;
    return;
  }

  if (static_cast<int>(step_index_) == new_step_index)
    return;

  hysteresis_count_++;
  VLOG(1) << "Incremented hysteresis count to " << hysteresis_count_
          << " (lux went from " << smoothed_lux_at_last_adjustment_ << " to "
          << new_lux << ") (" << name_ << ")";
  if (hysteresis_count_ >= kHysteresisThreshold) {
    step_index_ = new_step_index;
    double target_percent = GetTargetPercent();
    // Log the backlight brightness level that we're suggesting. Note that the
    // delegate may choose to ignore this suggestion for some other reason
    // (system is shutting down, user has manually requested a different level,
    // etc.).
    LOG(INFO) << "Transitioning " << name_ << " to " << target_percent
              << "% (step " << step_index_ << ") for lux " << new_lux << " ["
              << GetRecentReadingsString() << " ...]";
    smoothed_lux_at_last_adjustment_ = new_lux;
    hysteresis_count_ = 1;
    delegate_->SetBrightnessPercentForAmbientLight(
        target_percent, BrightnessChangeCause::AMBIENT_LIGHT);
    sent_initial_adjustment_ = true;
  }
}

double AmbientLightHandler::GetTargetPercent() const {
  CHECK_LT(step_index_, steps_.size());
  return power_source_ == PowerSource::AC
             ? steps_[step_index_].ac_target_percent
             : steps_[step_index_].battery_target_percent;
}

void AmbientLightHandler::UpdateSmoothedLux(int raw_lux) {
  // For the first sensor reading, use raw lux value directly without smoothing.
  if (hysteresis_state_ == HysteresisState::IMMEDIATE) {
    smoothed_lux_ = raw_lux;
  } else {
    smoothed_lux_ = smoothing_constant_ * raw_lux +
                    (1 - smoothing_constant_) * smoothed_lux_;
  }
}

}  // namespace power_manager::policy
