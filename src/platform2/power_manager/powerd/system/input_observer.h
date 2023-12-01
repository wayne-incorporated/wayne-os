// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_INPUT_OBSERVER_H_
#define POWER_MANAGER_POWERD_SYSTEM_INPUT_OBSERVER_H_

#include <base/observer_list_types.h>

#include "power_manager/common/power_constants.h"

namespace power_manager::system {

// Interface for classes interested in observing input events announced by the
// InputWatcher class.
class InputObserver : public base::CheckedObserver {
 public:
  ~InputObserver() override = default;

  // Called when the lid is opened or closed. LidState::NOT_PRESENT will never
  // be passed.
  virtual void OnLidEvent(LidState state) = 0;

  // Called when the tablet mode changes. TabletMode::UNSUPPORTED will never be
  // passed.
  virtual void OnTabletModeEvent(TabletMode mode) = 0;

  // Called when a power button event occurs.
  virtual void OnPowerButtonEvent(ButtonState state) = 0;

  // Called when the user's hands start or stop hovering over the touchpad.
  virtual void OnHoverStateChange(bool hovering) = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_INPUT_OBSERVER_H_
