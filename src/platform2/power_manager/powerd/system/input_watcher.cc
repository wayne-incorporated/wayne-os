// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/input_watcher.h"

#include <linux/input.h>
#include <unistd.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>

#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"
#include "power_manager/common/tracing.h"
#include "power_manager/powerd/system/event_device_interface.h"
#include "power_manager/powerd/system/input_observer.h"
#include "power_manager/powerd/system/udev.h"

namespace power_manager::system {

namespace {

const char kSysClassInputPath[] = "/sys/class/input";
const char kDevInputPath[] = "/dev/input";
const char kInputBaseName[] = "event";

const char kInputMatchPattern[] = "input*";
const char kUsbMatchString[] = "usb";
const char kBluetoothMatchString[] = "bluetooth";

// Given a string |name| consisting of kInputBaseName followed by a base-10
// integer, extracts the integer to |num_out|. Returns false if |name| didn't
// match the expected format.
bool GetInputNumber(const std::string& name, int* num_out) {
  if (!base::StartsWith(name, kInputBaseName, base::CompareCase::SENSITIVE))
    return false;
  size_t base_len = strlen(kInputBaseName);
  return base::StringToInt(name.substr(base_len, name.size() - base_len),
                           num_out);
}

// If |event| came from a lid switch, copies its state to |state_out| and
// returns true. Otherwise, leaves |state_out| untouched and returns false.
bool GetLidStateFromEvent(const input_event& event, LidState* state_out) {
  if (event.type != EV_SW || event.code != SW_LID)
    return false;

  *state_out = event.value == 1 ? LidState::CLOSED : LidState::OPEN;
  return true;
}

// If |event| came from a tablet mode switch, copies its state to |mode_out| and
// returns true. Otherwise, leaves |mode_out| untouched and returns false.
bool GetTabletModeFromEvent(const input_event& event, TabletMode* mode_out) {
  if (event.type != EV_SW || event.code != SW_TABLET_MODE)
    return false;

  *mode_out = event.value == 1 ? TabletMode::ON : TabletMode::OFF;
  return true;
}

// If |event| came from a power button, copies its state to |state_out| and
// returns true. Otherwise, leaves |state_out| untouched and returns false.
bool GetPowerButtonStateFromEvent(const input_event& event,
                                  ButtonState* state_out) {
  if (event.type != EV_KEY || event.code != KEY_POWER)
    return false;

  switch (event.value) {
    case 0:
      *state_out = ButtonState::UP;
      break;
    case 1:
      *state_out = ButtonState::DOWN;
      break;
    case 2:
      *state_out = ButtonState::REPEAT;
      break;
    default:
      LOG(ERROR) << "Unhandled button state " << event.value;
      return false;
  }
  return true;
}

}  // namespace

const char InputWatcher::kPowerButtonToSkip[] = "LNXPWRBN";
const char InputWatcher::kPowerButtonToSkipForLegacy[] = "isa";

InputWatcher::InputWatcher()
    : dev_input_path_(kDevInputPath),
      sys_class_input_path_(kSysClassInputPath),
      power_button_to_skip_(kPowerButtonToSkip),
      weak_ptr_factory_(this) {}

InputWatcher::~InputWatcher() {
  if (udev_)
    udev_->RemoveSubsystemObserver(kInputUdevSubsystem, this);
}

bool InputWatcher::Init(
    std::unique_ptr<EventDeviceFactoryInterface> event_device_factory,
    PrefsInterface* prefs,
    UdevInterface* udev) {
  event_device_factory_ = std::move(event_device_factory);
  udev_ = udev;

  prefs->GetBool(kUseLidPref, &use_lid_);
  if (!use_lid_)
    lid_state_ = LidState::NOT_PRESENT;

  bool legacy_power_button = false;
  if (prefs->GetBool(kLegacyPowerButtonPref, &legacy_power_button) &&
      legacy_power_button)
    power_button_to_skip_ = kPowerButtonToSkipForLegacy;

  prefs->GetBool(kDetectHoverPref, &detect_hover_);

  prefs->GetString(power_manager::kPreferredLidDevicePref,
                   &preferred_lid_device_);

  udev_->AddSubsystemObserver(kInputUdevSubsystem, this);

  std::vector<UdevDeviceInfo> input_device_list;
  if (udev_->GetSubsystemDevices(kInputUdevSubsystem, &input_device_list)) {
    for (auto const& input_device : input_device_list) {
      int num = -1;
      if (GetInputNumber(input_device.sysname, &num)) {
        HandleAddedInput(input_device.sysname, num, false /* notify_state */);
      }
    }
  } else {
    LOG(ERROR) << "Enumeration of existing input devices failed. User "
                  "interaction might not be recognized properly";
  }

  return true;
}

void InputWatcher::AddObserver(InputObserver* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void InputWatcher::RemoveObserver(InputObserver* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

LidState InputWatcher::QueryLidState() {
  if (!lid_device_)
    return LidState::NOT_PRESENT;

  const uint32_t device_types = GetDeviceTypes(lid_device_);
  while (true) {
    // Stop when we fail to read any more events.
    std::vector<input_event> events;
    auto ret = lid_device_->ReadEvents(&events);
    if (ret == EventDeviceInterface::ReadResult::kFailure) {
      break;
    } else if (ret == EventDeviceInterface::ReadResult::kNoDevice) {
      HandleRemovedInput(GetDeviceInputNumber(lid_device_));
      return LidState::NOT_PRESENT;
    }

    // Get the state from the last lid event (|events| may also contain non-lid
    // events).
    for (std::vector<input_event>::const_reverse_iterator it = events.rbegin();
         it != events.rend(); ++it) {
      if (GetLidStateFromEvent(*it, &lid_state_))
        break;
    }

    queued_events_.reserve(queued_events_.size() + events.size());
    for (auto event : events)
      queued_events_.emplace_back(event, device_types);
    VLOG(1) << "Queued " << events.size()
            << " event(s) while querying lid state";
  }

  if (!queued_events_.empty()) {
    send_queued_events_task_.Reset(base::BindOnce(
        &InputWatcher::SendQueuedEvents, base::Unretained(this)));
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, send_queued_events_task_.callback());
  }

  return lid_state_;
}

TabletMode InputWatcher::GetTabletMode() {
  return tablet_mode_;
}

bool InputWatcher::IsUSBInputDeviceConnected() const {
  base::FileEnumerator enumerator(
      sys_class_input_path_, false,
      static_cast<::base::FileEnumerator::FileType>(
          base::FileEnumerator::FILES | base::FileEnumerator::SHOW_SYM_LINKS),
      kInputMatchPattern);
  for (base::FilePath path = enumerator.Next(); !path.empty();
       path = enumerator.Next()) {
    base::FilePath symlink_path;
    if (!base::ReadSymbolicLink(path, &symlink_path))
      continue;
    const std::string& path_string = symlink_path.value();
    // Skip bluetooth devices, which may be identified as USB devices.
    if (path_string.find(kBluetoothMatchString) != std::string::npos)
      continue;
    // Now look for the USB devices that are not bluetooth.
    size_t position = path_string.find(kUsbMatchString);
    if (position == std::string::npos)
      continue;
    // Now that the string "usb" has been found, make sure it is a whole word
    // and not just part of another word like "busbreaker".
    bool usb_at_word_head =
        position == 0 || !base::IsAsciiAlpha(path_string.at(position - 1));
    bool usb_at_word_tail =
        position + strlen(kUsbMatchString) == path_string.size() ||
        !base::IsAsciiAlpha(path_string.at(position + strlen(kUsbMatchString)));
    if (usb_at_word_head && usb_at_word_tail)
      return true;
  }
  return false;
}

void InputWatcher::OnUdevEvent(const UdevEvent& event) {
  DCHECK_EQ(event.device_info.subsystem, kInputUdevSubsystem);
  int input_num = -1;
  if (GetInputNumber(event.device_info.sysname, &input_num)) {
    if (event.action == UdevEvent::Action::ADD) {
      HandleAddedInput(event.device_info.sysname, input_num,
                       true /* notify_state */);
    } else if (event.action == UdevEvent::Action::REMOVE) {
      HandleRemovedInput(input_num);
    }
  }
}

uint32_t InputWatcher::GetDeviceTypes(
    const EventDeviceInterface* device) const {
  uint32_t device_types = DEVICE_NONE;
  if (power_button_devices_.count(device))
    device_types |= DEVICE_POWER_BUTTON;
  if (device == lid_device_)
    device_types |= DEVICE_LID_SWITCH;
  if (device == tablet_mode_device_)
    device_types |= DEVICE_TABLET_MODE_SWITCH;
  if (device == hover_device_)
    device_types |= DEVICE_HOVER;
  return device_types;
}

int InputWatcher::GetDeviceInputNumber(
    const EventDeviceInterface* device) const {
  for (const auto& entry : event_devices_) {
    if (entry.second.get() == device)
      return entry.first;
  }
  return -1;
}

void InputWatcher::OnNewEvents(int input_num, EventDeviceInterface* device) {
  SendQueuedEvents();

  std::vector<input_event> events;
  switch (device->ReadEvents(&events)) {
    case EventDeviceInterface::ReadResult::kFailure:
      return;
    case EventDeviceInterface::ReadResult::kNoDevice:
      HandleRemovedInput(input_num);
      return;
    case EventDeviceInterface::ReadResult::kSuccess:
      break;
  }

  VLOG(1) << "Read " << events.size() << " event(s) from "
          << device->GetDebugName();
  const uint32_t device_types = GetDeviceTypes(device);
  for (const input_event& event : events) {
    // Update |lid_state_| here instead of in ProcessEvent() so we can avoid
    // modifying it in response to queued events.
    if (device_types & DEVICE_LID_SWITCH)
      GetLidStateFromEvent(event, &lid_state_);
    ProcessEvent(event, device_types);
  }
}

void InputWatcher::ProcessEvent(const input_event& event,
                                uint32_t device_types) {
  TRACE_EVENT("power", "InputWatcher::ProcessEvent", "type", event.type, "code",
              event.code, "value", event.value, "device_types", device_types);
  LidState lid_state = LidState::OPEN;
  if ((device_types & DEVICE_LID_SWITCH) &&
      GetLidStateFromEvent(event, &lid_state)) {
    VLOG(1) << "Notifying observers about lid " << LidStateToString(lid_state)
            << " event";
    for (InputObserver& observer : observers_)
      observer.OnLidEvent(lid_state);
  }

  TabletMode tablet_mode = TabletMode::OFF;
  if (device_types & DEVICE_TABLET_MODE_SWITCH &&
      GetTabletModeFromEvent(event, &tablet_mode)) {
    tablet_mode_ = tablet_mode;
    VLOG(1) << "Notifying observers about tablet mode "
            << TabletModeToString(tablet_mode) << " event";
    for (InputObserver& observer : observers_)
      observer.OnTabletModeEvent(tablet_mode);
  }

  ButtonState button_state = ButtonState::DOWN;
  if ((device_types & DEVICE_POWER_BUTTON) &&
      GetPowerButtonStateFromEvent(event, &button_state)) {
    VLOG(1) << "Notifying observers about power button "
            << ButtonStateToString(button_state) << " event";
    for (InputObserver& observer : observers_)
      observer.OnPowerButtonEvent(button_state);
  }

  if (device_types & DEVICE_HOVER)
    ProcessHoverEvent(event);
}

void InputWatcher::ProcessHoverEvent(const input_event& event) {
  if (event.type == EV_ABS && event.code == ABS_MT_SLOT) {
    VLOG(2) << "ABS_MT_SLOT " << event.value;
    // ABS_MT_SLOT events announce the slot that following multitouch events
    // will refer to.
    if (event.value < 0 ||
        event.value >=
            static_cast<int>(sizeof(multitouch_slots_hover_state_) * 8)) {
      LOG(WARNING) << "Ignoring ABS_MT_SLOT event for slot " << event.value;
      current_multitouch_slot_ = -1;
    } else {
      current_multitouch_slot_ = event.value;
    }
  } else if (event.type == EV_ABS && event.code == ABS_MT_TRACKING_ID) {
    VLOG(2) << "ABS_MT_TRACKING_ID " << event.value;
    // ABS_MT_TRACKING_ID events associate a tracking ID with the current slot,
    // with -1 indicating that the slot is unused. Use them as a proxy for
    // whether the slot is reporting a hover (or touch).
    if (current_multitouch_slot_ >= 0) {
      const uint64_t slot_bit = static_cast<uint64_t>(1)
                                << current_multitouch_slot_;
      if (event.value >= 0)
        multitouch_slots_hover_state_ |= slot_bit;
      else
        multitouch_slots_hover_state_ &= ~slot_bit;
    }
  } else if (event.type == EV_ABS && event.code == ABS_DISTANCE) {
    // For single-touch presence-only hover touchpads, ABS_DISTANCE indicates
    // the distance above the pad the single-touch finger is hovering
    VLOG(2) << "ABS_DISTANCE " << event.value;
    single_touch_hover_distance_nonzero_ = (event.value > 0);
  } else if (event.type == EV_KEY && event.code == BTN_TOOL_FINGER) {
    // For single-touch presence-only hover touchpads, BTN_TOOL_FINGER tells
    // us if the single-touch contact is valid (if we should believe the
    // value in ABS_DISTANCE)
    VLOG(2) << "BTN_TOOL_FINGER " << event.value;
    single_touch_hover_valid_ = (event.value == 1);
  } else if (event.type == EV_SYN && event.code == SYN_REPORT) {
    // SYN_REPORT events indicate the end of the current set of multitouch data.
    // Check whether the overall hovering state is different from before and
    // notify observers if so.
    VLOG(2) << "SYN_REPORT";
    bool multi_touch_hovering = multitouch_slots_hover_state_ != 0;
    bool single_touch_hovering =
        (single_touch_hover_distance_nonzero_ && single_touch_hover_valid_);
    bool hovering = multi_touch_hovering || single_touch_hovering;
    if (hovering != hovering_) {
      VLOG(1) << "Notifying observers about hover state change to "
              << (hovering ? "on" : "off");
      hovering_ = hovering;
      for (InputObserver& observer : observers_)
        observer.OnHoverStateChange(hovering_);
    }
  }
}

void InputWatcher::HandleAddedInput(const std::string& input_name,
                                    int input_num,
                                    bool notify_state) {
  if (event_devices_.count(input_num) > 0) {
    LOG(WARNING) << "Input " << input_num << " already registered";
    return;
  }

  const base::FilePath path = dev_input_path_.Append(input_name);
  std::shared_ptr<EventDeviceInterface> device(
      event_device_factory_->Open(path));
  if (!device.get()) {
    LOG(ERROR) << "Failed to open " << path.value();
    return;
  }

  bool should_watch = false;

  const std::string phys = device->GetPhysPath();
  if (base::StartsWith(phys, power_button_to_skip_,
                       base::CompareCase::SENSITIVE)) {
    VLOG(1) << "Skipping event device with phys path: " << phys;
  } else if (device->IsPowerButton()) {
    LOG(INFO) << "Watching power button: " << device->GetDebugName();
    should_watch = true;
    power_button_devices_.insert(device.get());
  }

  // Note that it's possible for a power button and lid switch to share a single
  // event device.
  if (use_lid_ && device->IsLidSwitch()) {
    if (lid_device_ && (preferred_lid_device_.empty() ||
                        lid_device_->GetName() == preferred_lid_device_ ||
                        device->GetName() != preferred_lid_device_)) {
      LOG(WARNING) << "Skipping additional lid switch device "
                   << device->GetDebugName();
    } else {
      LOG(INFO) << "Watching lid switch: " << device->GetDebugName();
      should_watch = true;
      lid_device_ = device.get();
      lid_state_ = device->GetInitialLidState();
      VLOG(1) << "Initial lid state is " << LidStateToString(lid_state_);
      if (notify_state) {
        for (InputObserver& observer : observers_)
          observer.OnLidEvent(lid_state_);
      }
    }
  }

  if (device->IsTabletModeSwitch()) {
    if (tablet_mode_device_) {
      LOG(WARNING) << "Skipping additional tablet mode switch "
                   << device->GetDebugName();
    } else {
      LOG(INFO) << "Watching tablet mode switch: " << device->GetDebugName();
      should_watch = true;
      tablet_mode_device_ = device.get();
      tablet_mode_ = device->GetInitialTabletMode();
      VLOG(1) << "Initial tablet mode state is "
              << TabletModeToString(tablet_mode_);
      if (notify_state) {
        for (InputObserver& observer : observers_)
          observer.OnTabletModeEvent(tablet_mode_);
      }
    }
  }

  if (detect_hover_ && device->HoverSupported() && device->HasLeftButton()) {
    if (hover_device_) {
      LOG(WARNING) << "Skipping additional hover device "
                   << device->GetDebugName();
    } else {
      LOG(INFO) << "Watching hover device: " << device->GetDebugName();
      should_watch = true;
      hover_device_ = device.get();
    }
  }

  if (device->IsCrosFp()) {
    should_watch = true;
    LOG(INFO) << "Watching fingerprint device: " << device->GetDebugName();
  }

  if (should_watch) {
    device->WatchForEvents(base::BindRepeating(
        &InputWatcher::OnNewEvents, weak_ptr_factory_.GetWeakPtr(), input_num,
        base::Unretained(device.get())));
    event_devices_.insert(std::make_pair(input_num, device));
  } else {
    VLOG(1) << "Event device with phys path " << device->GetDebugName()
            << " is not monitored for input events";
  }
}

void InputWatcher::HandleRemovedInput(int input_num) {
  InputMap::iterator it = event_devices_.find(input_num);
  if (it != event_devices_.end()) {
    LOG(INFO) << "Stopping watching " << it->second->GetDebugName();
    power_button_devices_.erase(it->second.get());
    if (lid_device_ == it->second.get())
      lid_device_ = nullptr;
    if (tablet_mode_device_ == it->second.get())
      tablet_mode_device_ = nullptr;
    if (hover_device_ == it->second.get())
      hover_device_ = nullptr;
    event_devices_.erase(it);
  }
}

void InputWatcher::SendQueuedEvents() {
  TRACE_EVENT("power", "InputWatcher::SendQueuedEvents");
  for (auto event_pair : queued_events_)
    ProcessEvent(event_pair.first, event_pair.second);
  queued_events_.clear();
}

}  // namespace power_manager::system
