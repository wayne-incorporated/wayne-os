// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/event_device_stub.h"

#include <base/logging.h>

namespace power_manager::system {

void EventDeviceStub::AppendEvent(uint16_t type, uint16_t code, int32_t value) {
  input_event event;
  memset(&event, 0, sizeof(event));
  event.type = type;
  event.code = code;
  event.value = value;
  events_.push_back(event);
}

void EventDeviceStub::NotifyAboutEvents() {
  if (!new_events_cb_.is_null())
    new_events_cb_.Run();
}

std::string EventDeviceStub::GetDebugName() {
  return debug_name_;
}

std::string EventDeviceStub::GetName() {
  return name_;
}

std::string EventDeviceStub::GetPhysPath() {
  return phys_path_;
}

bool EventDeviceStub::IsCrosFp() {
  return is_cros_fp_;
}

bool EventDeviceStub::IsLidSwitch() {
  return is_lid_switch_;
}

bool EventDeviceStub::IsTabletModeSwitch() {
  return is_tablet_mode_switch_;
}

bool EventDeviceStub::IsPowerButton() {
  return is_power_button_;
}

bool EventDeviceStub::HoverSupported() {
  return hover_supported_;
}

bool EventDeviceStub::HasLeftButton() {
  return has_left_button_;
}

LidState EventDeviceStub::GetInitialLidState() {
  return initial_lid_state_;
}

TabletMode EventDeviceStub::GetInitialTabletMode() {
  return initial_tablet_mode_;
}

EventDeviceStub::ReadResult EventDeviceStub::ReadEvents(
    std::vector<input_event>* events_out) {
  if (device_disconnected_)
    return ReadResult::kNoDevice;
  if (events_.empty())
    return ReadResult::kFailure;

  events_out->swap(events_);
  events_.clear();
  return ReadResult::kSuccess;
}

void EventDeviceStub::WatchForEvents(
    const base::RepeatingClosure& new_events_cb) {
  new_events_cb_ = new_events_cb;
}

void EventDeviceFactoryStub::RegisterDevice(
    const base::FilePath& path, std::shared_ptr<EventDeviceInterface> device) {
  devices_[path] = device;
}

std::shared_ptr<EventDeviceInterface> EventDeviceFactoryStub::Open(
    const base::FilePath& path) {
  auto it = devices_.find(path);
  return it != devices_.end() ? it->second
                              : std::shared_ptr<EventDeviceInterface>();
}

}  // namespace power_manager::system
