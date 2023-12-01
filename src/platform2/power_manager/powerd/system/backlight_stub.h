// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_BACKLIGHT_STUB_H_
#define POWER_MANAGER_POWERD_SYSTEM_BACKLIGHT_STUB_H_

#include <base/compiler_specific.h>
#include <base/observer_list.h>
#include <base/time/time.h>

#include "power_manager/common/clock.h"
#include "power_manager/powerd/system/backlight_interface.h"
#include "power_manager/powerd/system/backlight_observer.h"

namespace power_manager::system {

// Stub implementation of BacklightInterface for testing.
class BacklightStub : public BacklightInterface {
 public:
  BacklightStub(int64_t max_level,
                int64_t current_level,
                BrightnessScale scale);
  BacklightStub(const BacklightStub&) = delete;
  BacklightStub& operator=(const BacklightStub&) = delete;

  ~BacklightStub() override = default;

  void set_clock(Clock* clock) { clock_ = clock; }
  void set_device_exists(bool exists) { device_exists_ = exists; }
  void set_max_level(int64_t level) { max_level_ = level; }
  void set_current_level(int64_t level) { current_level_ = level; }
  void set_transition_in_progress(bool in_progress) {
    transition_in_progress_ = in_progress;
  }
  void set_should_fail(bool should_fail) { should_fail_ = should_fail; }

  int64_t current_level() const { return current_level_; }
  base::TimeDelta current_interval() const { return current_interval_; }
  base::TimeTicks last_set_brightness_level_time() const {
    return last_set_brightness_level_time_;
  }

  // Tells |observers_| that the underlying device changed.
  void NotifyDeviceChanged();

  // BacklightInterface implementation:
  void AddObserver(BacklightObserver* observer) override;
  void RemoveObserver(BacklightObserver* observer) override;
  bool DeviceExists() const override;
  int64_t GetMaxBrightnessLevel() override;
  int64_t GetCurrentBrightnessLevel() override;
  bool SetBrightnessLevel(int64_t level, base::TimeDelta interval) override;
  BrightnessScale GetBrightnessScale() override;
  bool TransitionInProgress() const override;

  void SetBrightnessScale(BacklightInterface::BrightnessScale scale);

 private:
  base::ObserverList<BacklightObserver> observers_;

  // Not owned and may be null. Used to update
  // |last_set_brightness_level_time_|.
  Clock* clock_ = nullptr;

  // True if the underlying backlight device exists.
  bool device_exists_ = true;

  // Maximum backlight level.
  int64_t max_level_ = -1;

  // Most-recently-set brightness level.
  int64_t current_level_ = -1;

  // |interval| parameter passed to most recent SetBrightnessLevel() call.
  base::TimeDelta current_interval_;

  // Return value for TransitionInProgress().
  bool transition_in_progress_ = false;

  // Should we report failure in response to future requests?
  bool should_fail_ = false;

  // Last time at which SetBrightnessLevel() was called with a new level.
  base::TimeTicks last_set_brightness_level_time_;

  // Return value for GetBrightnessScale()
  BrightnessScale scale_ = BrightnessScale::kUnknown;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_BACKLIGHT_STUB_H_
