// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/internal_backlight.h"

#include <cmath>
#include <string>

#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/time/time.h>
#include <linux/fb.h>

#include "power_manager/common/clock.h"
#include "power_manager/common/tracing.h"
#include "power_manager/common/util.h"

namespace power_manager::system {

namespace {

// When animating a brightness level transition, amount of time to wait between
// each update.
constexpr base::TimeDelta kTransitionInterval = base::Milliseconds(20);

}  // namespace

const char InternalBacklight::kBrightnessFilename[] = "brightness";
const char InternalBacklight::kMaxBrightnessFilename[] = "max_brightness";
const char InternalBacklight::kBlPowerFilename[] = "bl_power";
const char InternalBacklight::kScaleFilename[] = "scale";

bool InternalBacklight::Init(const base::FilePath& base_path,
                             const std::string& pattern) {
  base::FileEnumerator enumerator(base_path, false,
                                  base::FileEnumerator::DIRECTORIES, pattern);

  // Find the backlight interface with greatest granularity (highest max).
  for (base::FilePath device_path = enumerator.Next(); !device_path.empty();
       device_path = enumerator.Next()) {
    if (device_path.BaseName().value()[0] == '.')
      continue;

    const base::FilePath max_brightness_path =
        device_path.Append(kMaxBrightnessFilename);
    if (!base::PathExists(max_brightness_path)) {
      LOG(WARNING) << "Can't find " << max_brightness_path.value();
      continue;
    }

    const base::FilePath brightness_path =
        device_path.Append(kBrightnessFilename);
    if (access(brightness_path.value().c_str(), R_OK | W_OK) != 0) {
      LOG(WARNING) << "Can't write to " << brightness_path.value();
      continue;
    }

    int64_t max_level = 0;
    if (!util::ReadInt64File(max_brightness_path, &max_level))
      continue;

    if (max_level <= max_brightness_level_)
      continue;

    device_path_ = device_path;
    brightness_path_ = brightness_path;
    max_brightness_path_ = max_brightness_path;
    max_brightness_level_ = max_level;

    const base::FilePath power_path = device_path.Append(kBlPowerFilename);
    if (base::PathExists(power_path))
      bl_power_path_ = power_path;

    const base::FilePath scale_path = device_path.Append(kScaleFilename);
    if (base::PathExists(scale_path)) {
      std::string scale;
      util::ReadStringFile(scale_path, &scale);
      if (scale == "linear")
        brightness_scale_ = BrightnessScale::kLinear;
      else if (scale == "non-linear")
        brightness_scale_ = BrightnessScale::kNonLinear;
      else
        brightness_scale_ = BrightnessScale::kUnknown;
    }
  }

  if (max_brightness_level_ <= 0)
    return false;

  util::ReadInt64File(brightness_path_, &current_brightness_level_);
  return true;
}

bool InternalBacklight::TriggerTransitionTimeoutForTesting() {
  CHECK(transition_timer_.IsRunning());
  HandleTransitionTimeout();
  return transition_timer_.IsRunning();
}

void InternalBacklight::AddObserver(BacklightObserver* observer) {}

void InternalBacklight::RemoveObserver(BacklightObserver* observer) {}

bool InternalBacklight::DeviceExists() const {
  return true;
}

int64_t InternalBacklight::GetMaxBrightnessLevel() {
  return max_brightness_level_;
}

int64_t InternalBacklight::GetCurrentBrightnessLevel() {
  return current_brightness_level_;
}

bool InternalBacklight::DoSetBrightnessLevel(int64_t level,
                                             base::TimeDelta interval) {
  if (level == current_brightness_level_) {
    CancelTransition();
    return true;
  }

  if (interval <= kTransitionInterval) {
    CancelTransition();
    return WriteBrightness(level);
  }

  transition_start_time_ = clock_->GetCurrentTime();
  transition_end_time_ = transition_start_time_ + interval;
  transition_start_level_ = current_brightness_level_;
  transition_end_level_ = level;
  if (!transition_timer_.IsRunning()) {
    transition_timer_.Start(FROM_HERE, kTransitionInterval, this,
                            &InternalBacklight::HandleTransitionTimeout);
    transition_timer_start_time_ = transition_start_time_;
  }
  return true;
}

bool InternalBacklight::SetBrightnessLevel(int64_t level,
                                           base::TimeDelta interval) {
  if (brightness_path_.empty()) {
    LOG(ERROR) << "Cannot find backlight brightness file.";
    return false;
  }

  return DoSetBrightnessLevel(level, interval);
}

BacklightInterface::BrightnessScale InternalBacklight::GetBrightnessScale() {
  return brightness_scale_;
}

bool InternalBacklight::TransitionInProgress() const {
  return transition_timer_.IsRunning();
}

bool InternalBacklight::WriteBrightness(int64_t new_level) {
  // If the backlight is about to be turned on, write FB_BLANK_UNBLANK
  // to bl_power first.
  if (current_brightness_level_ == 0 && !bl_power_path_.empty())
    util::WriteInt64File(bl_power_path_, FB_BLANK_UNBLANK);

  if (!util::WriteInt64File(brightness_path_, new_level))
    return false;

  current_brightness_level_ = new_level;

  // If the backlight level just went to 0, write FB_BLANK_POWERDOWN
  // to bl_power.
  if (current_brightness_level_ == 0 && !bl_power_path_.empty())
    util::WriteInt64File(bl_power_path_, FB_BLANK_POWERDOWN);

  return true;
}

void InternalBacklight::HandleTransitionTimeout() {
  TRACE_EVENT("power", "InternalBacklight::HandleTransitionTimeout");
  base::TimeTicks now = clock_->GetCurrentTime();
  int64_t new_level = 0;

  if (now >= transition_end_time_) {
    new_level = transition_end_level_;
    transition_timer_.Stop();
  } else {
    double transition_fraction =
        (now - transition_start_time_).InMillisecondsF() /
        (transition_end_time_ - transition_start_time_).InMillisecondsF();
    int64_t intermediate_amount = lround(
        transition_fraction *
        static_cast<double>((transition_end_level_ - transition_start_level_)));
    new_level = transition_start_level_ + intermediate_amount;
  }

  if (new_level == current_brightness_level_)
    return;

  WriteBrightness(new_level);
}

void InternalBacklight::CancelTransition() {
  transition_timer_.Stop();
  transition_start_time_ = base::TimeTicks();
  transition_end_time_ = base::TimeTicks();
  transition_start_level_ = current_brightness_level_;
  transition_end_level_ = current_brightness_level_;
}

}  // namespace power_manager::system
