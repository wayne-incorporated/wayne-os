// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_BACKLIGHT_CONTROLLER_OBSERVER_H_
#define POWER_MANAGER_POWERD_POLICY_BACKLIGHT_CONTROLLER_OBSERVER_H_

#include <base/observer_list_types.h>

#include "power_manager/powerd/policy/backlight_controller.h"
#include "power_manager/proto_bindings/backlight.pb.h"

namespace power_manager::policy {

// Interface for observing changes made by BacklightControllers.
class BacklightControllerObserver : public base::CheckedObserver {
 public:
  // Invoked when the brightness level is changed.  |brightness_percent| is the
  // current brightness in the range [0.0, 100.0].
  virtual void OnBrightnessChange(double brightness_percent,
                                  BacklightBrightnessChange_Cause cause,
                                  BacklightController* source) {}

 protected:
  ~BacklightControllerObserver() override = default;
};

}  // namespace power_manager::policy

#endif  // POWER_MANAGER_POWERD_POLICY_BACKLIGHT_CONTROLLER_OBSERVER_H_
