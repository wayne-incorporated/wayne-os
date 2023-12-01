// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_EVENT_DEVICE_STUB_H_
#define POWER_MANAGER_POWERD_SYSTEM_EVENT_DEVICE_STUB_H_

#include "power_manager/powerd/system/event_device_interface.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <linux/input.h>

namespace power_manager::system {

// EventDeviceInterface implementation that returns canned values for testing.
class EventDeviceStub : public EventDeviceInterface {
 public:
  EventDeviceStub() = default;
  EventDeviceStub(const EventDeviceStub&) = delete;
  EventDeviceStub& operator=(const EventDeviceStub&) = delete;

  ~EventDeviceStub() override = default;

  const base::RepeatingClosure& new_events_cb() const { return new_events_cb_; }
  void set_debug_name(const std::string& name) { debug_name_ = name; }
  void set_name(const std::string& name) { name_ = name; }
  void set_phys_path(const std::string& path) { phys_path_ = path; }
  void set_is_cros_fp(bool is_cros_fp) { is_cros_fp_ = is_cros_fp; }
  void set_is_lid_switch(bool is_switch) { is_lid_switch_ = is_switch; }
  void set_is_tablet_mode_switch(bool is_switch) {
    is_tablet_mode_switch_ = is_switch;
  }
  void set_is_power_button(bool is_button) { is_power_button_ = is_button; }
  void set_hover_supported(bool supported) { hover_supported_ = supported; }
  void set_has_left_button(bool has_button) { has_left_button_ = has_button; }
  void set_initial_lid_state(LidState state) { initial_lid_state_ = state; }
  void set_initial_tablet_mode(TabletMode mode) { initial_tablet_mode_ = mode; }
  void set_device_disconnected() { device_disconnected_ = true; }

  // Appends an event with the passed-in values to the list to be returned by
  // the next call to ReadEvents(). Arguments correspond to fields in the
  // input_event struct.
  void AppendEvent(uint16_t type, uint16_t code, int32_t value);

  // Notifies |new_events_cb_| that new events are available.
  void NotifyAboutEvents();

  // Implementation of EventDeviceInterface.
  std::string GetDebugName() override;
  std::string GetName() override;
  std::string GetPhysPath() override;
  bool IsCrosFp() override;
  bool IsLidSwitch() override;
  bool IsTabletModeSwitch() override;
  bool IsPowerButton() override;
  bool HoverSupported() override;
  bool HasLeftButton() override;
  LidState GetInitialLidState() override;
  TabletMode GetInitialTabletMode() override;
  ReadResult ReadEvents(std::vector<input_event>* events_out) override;
  void WatchForEvents(const base::RepeatingClosure& new_events_cb) override;

 private:
  std::string debug_name_;
  std::string name_;
  std::string phys_path_;
  bool is_cros_fp_ = false;
  bool is_lid_switch_ = false;
  bool is_tablet_mode_switch_ = false;
  bool is_power_button_ = false;
  bool hover_supported_ = false;
  bool has_left_button_ = false;
  bool device_disconnected_ = false;
  LidState initial_lid_state_ = LidState::OPEN;
  TabletMode initial_tablet_mode_ = TabletMode::OFF;

  // Events to be returned by the next call to ReadEvents().
  std::vector<input_event> events_;

  // Callback registered via WatchForEvents() and called by NotifyAboutEvents().
  base::RepeatingClosure new_events_cb_;
};

// EventDeviceFactoryInterface interface that returns EventDeviceStubs for
// testing.
class EventDeviceFactoryStub : public EventDeviceFactoryInterface {
 public:
  EventDeviceFactoryStub() = default;
  EventDeviceFactoryStub(const EventDeviceFactoryStub&) = delete;
  EventDeviceFactoryStub& operator=(const EventDeviceFactoryStub&) = delete;

  ~EventDeviceFactoryStub() override = default;

  // Adds a mapping in |devices_| so that |device| will be returned in response
  // to Open() calls for |path|.
  void RegisterDevice(const base::FilePath& path,
                      std::shared_ptr<EventDeviceInterface> device);

  // Implementation of EventDeviceFactoryInterface.
  std::shared_ptr<EventDeviceInterface> Open(
      const base::FilePath& path) override;

 private:
  // Map from device paths to registered devices.
  std::map<base::FilePath, std::shared_ptr<EventDeviceInterface>> devices_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_EVENT_DEVICE_STUB_H_
