// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/backlight_stub.h"

#include <base/check.h>

namespace power_manager::system {

BacklightStub::BacklightStub(int64_t max_level,
                             int64_t current_level,
                             BrightnessScale scale)
    : max_level_(max_level), current_level_(current_level), scale_(scale) {}

void BacklightStub::NotifyDeviceChanged() {
  for (BacklightObserver& observer : observers_)
    observer.OnBacklightDeviceChanged(this);
}

void BacklightStub::AddObserver(BacklightObserver* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void BacklightStub::RemoveObserver(BacklightObserver* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

bool BacklightStub::DeviceExists() const {
  return device_exists_;
}

int64_t BacklightStub::GetMaxBrightnessLevel() {
  return max_level_;
}

int64_t BacklightStub::GetCurrentBrightnessLevel() {
  return current_level_;
}

bool BacklightStub::SetBrightnessLevel(int64_t level,
                                       base::TimeDelta interval) {
  if (level != current_level_) {
    last_set_brightness_level_time_ =
        clock_ ? clock_->GetCurrentTime() : base::TimeTicks::Now();
  }
  if (should_fail_)
    return false;
  current_level_ = level;
  current_interval_ = interval;
  return true;
}

BacklightInterface::BrightnessScale BacklightStub::GetBrightnessScale() {
  return scale_;
}

bool BacklightStub::TransitionInProgress() const {
  return transition_in_progress_;
}

void BacklightStub::SetBrightnessScale(
    BacklightInterface::BrightnessScale scale) {
  scale_ = scale;
}

}  // namespace power_manager::system
