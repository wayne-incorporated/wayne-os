// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/input_watcher_stub.h"

#include "power_manager/powerd/system/input_observer.h"

#include <base/check.h>

namespace power_manager::system {

void InputWatcherStub::NotifyObserversAboutLidState() {
  for (InputObserver& observer : observers_)
    observer.OnLidEvent(lid_state_);
}

void InputWatcherStub::NotifyObserversAboutTabletMode() {
  for (InputObserver& observer : observers_)
    observer.OnTabletModeEvent(tablet_mode_);
}

void InputWatcherStub::NotifyObserversAboutPowerButtonEvent(ButtonState state) {
  for (InputObserver& observer : observers_)
    observer.OnPowerButtonEvent(state);
}

void InputWatcherStub::NotifyObserversAboutHoverState(bool hovering) {
  for (InputObserver& observer : observers_)
    observer.OnHoverStateChange(hovering);
}

void InputWatcherStub::AddObserver(InputObserver* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void InputWatcherStub::RemoveObserver(InputObserver* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

LidState InputWatcherStub::QueryLidState() {
  return lid_state_;
}

TabletMode InputWatcherStub::GetTabletMode() {
  return tablet_mode_;
}

bool InputWatcherStub::IsUSBInputDeviceConnected() const {
  return usb_input_device_connected_;
}

}  // namespace power_manager::system
