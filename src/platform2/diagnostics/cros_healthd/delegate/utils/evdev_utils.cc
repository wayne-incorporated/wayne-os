// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/delegate/utils/evdev_utils.h"

#include <algorithm>
#include <fcntl.h>
#include <libevdev/libevdev.h>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/logging.h>

#include "diagnostics/base/file_utils.h"
#include "diagnostics/cros_healthd/delegate/utils/libevdev_wrapper_impl.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

constexpr char kDevInputPath[] = "/dev/input/";

std::optional<mojom::InputTouchButton> EventCodeToInputTouchButton(
    unsigned int code) {
  switch (code) {
    case BTN_LEFT:
      return mojom::InputTouchButton::kLeft;
    case BTN_MIDDLE:
      return mojom::InputTouchButton::kMiddle;
    case BTN_RIGHT:
      return mojom::InputTouchButton::kRight;
    default:
      return std::nullopt;
  }
}

mojom::NullableUint32Ptr FetchOptionalUnsignedSlotValue(LibevdevWrapper* dev,
                                                        unsigned int slot,
                                                        unsigned int code) {
  int out_value;
  if (dev->FetchSlotValue(slot, code, &out_value) && out_value >= 0) {
    return mojom::NullableUint32::New(out_value);
  }
  return nullptr;
}

std::vector<mojom::TouchPointInfoPtr> FetchTouchPoints(LibevdevWrapper* dev) {
  int num_slot = dev->GetNumSlots();
  if (num_slot < 0) {
    LOG(ERROR) << "The evdev device does not provide any slots.";
    return {};
  }
  std::vector<mojom::TouchPointInfoPtr> points;
  for (int slot = 0; slot < num_slot; ++slot) {
    int value_x, value_y, id;
    if (dev->FetchSlotValue(slot, ABS_MT_POSITION_X, &value_x) &&
        dev->FetchSlotValue(slot, ABS_MT_POSITION_Y, &value_y) &&
        dev->FetchSlotValue(slot, ABS_MT_TRACKING_ID, &id)) {
      // A non-negative tracking id is interpreted as a contact, and the value
      // -1 denotes an unused slot.
      if (id >= 0 && value_x >= 0 && value_y >= 0) {
        auto point_info = mojom::TouchPointInfo::New();
        point_info->tracking_id = id;
        point_info->x = value_x;
        point_info->y = value_y;
        point_info->pressure =
            FetchOptionalUnsignedSlotValue(dev, slot, ABS_MT_PRESSURE);
        point_info->touch_major =
            FetchOptionalUnsignedSlotValue(dev, slot, ABS_MT_TOUCH_MAJOR);
        point_info->touch_minor =
            FetchOptionalUnsignedSlotValue(dev, slot, ABS_MT_TOUCH_MINOR);
        points.push_back(std::move(point_info));
      }
    }
  }
  return points;
}

}  // namespace

EvdevUtil::EvdevDevice::EvdevDevice(base::ScopedFD fd,
                                    std::unique_ptr<LibevdevWrapper> dev)
    : fd_(std::move(fd)), dev_(std::move(dev)) {}

EvdevUtil::EvdevDevice::~EvdevDevice() = default;

bool EvdevUtil::EvdevDevice::StarWatchingEvents(
    base::RepeatingCallback<void(LibevdevWrapper*)> on_evdev_event) {
  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      fd_.get(), base::BindRepeating(on_evdev_event, dev_.get()));
  return !!watcher_;
}

EvdevUtil::EvdevUtil(std::unique_ptr<Delegate> delegate,
                     bool allow_multiple_devices)
    : EvdevUtil(std::move(delegate),
                allow_multiple_devices,
                base::BindRepeating(&LibevdevWrapperImpl::Create)) {}

EvdevUtil::EvdevUtil(std::unique_ptr<Delegate> delegate,
                     bool allow_multiple_devices,
                     LibevdevWrapperFactoryMethod factory_method)
    : allow_multiple_devices_(allow_multiple_devices),
      delegate_(std::move(delegate)) {
  Initialize(factory_method);
}

EvdevUtil::~EvdevUtil() = default;

void EvdevUtil::Initialize(LibevdevWrapperFactoryMethod factory_method) {
  base::FileEnumerator file_enum(GetRootedPath(kDevInputPath),
                                 /*recursive=*/false,
                                 base::FileEnumerator::FILES);
  for (auto path = file_enum.Next(); !path.empty(); path = file_enum.Next()) {
    if (Initialize(path, factory_method) && !allow_multiple_devices_) {
      return;
    }
  }

  if (devs_.empty()) {
    LOG(ERROR) << "EvdevUtil can't find target, initialization fail";
    delegate_->InitializationFail(/*custom_reason = */ 0,
                                  "EvdevUtil can't find target.");
  }
}

bool EvdevUtil::Initialize(const base::FilePath& path,
                           LibevdevWrapperFactoryMethod factory_method) {
  auto fd = base::ScopedFD(open(path.value().c_str(), O_RDONLY | O_NONBLOCK));
  if (!fd.is_valid()) {
    return false;
  }

  auto dev = factory_method.Run(fd.get());
  if (!dev) {
    return false;
  }

  if (!delegate_->IsTarget(dev.get())) {
    return false;
  }

  LibevdevWrapper* const libevdev_ptr = dev.get();

  auto evdev_device =
      std::make_unique<EvdevDevice>(std::move(fd), std::move(dev));
  if (!evdev_device->StarWatchingEvents(base::BindRepeating(
          &EvdevUtil::OnEvdevEvent, base::Unretained(this)))) {
    LOG(ERROR) << "Fail to monitor evdev node: " << path;
    return false;
  }

  devs_.push_back(std::move(evdev_device));

  LOG(INFO) << "Connected to evdev node: " << path
            << ", device name: " << libevdev_ptr->GetName();
  delegate_->ReportProperties(libevdev_ptr);
  return true;
}

void EvdevUtil::OnEvdevEvent(LibevdevWrapper* dev) {
  input_event ev;
  int rc = 0;

  do {
    rc = dev->NextEvent(LIBEVDEV_READ_FLAG_NORMAL | LIBEVDEV_READ_FLAG_BLOCKING,
                        &ev);
    if (rc == LIBEVDEV_READ_STATUS_SUCCESS) {
      delegate_->FireEvent(ev, dev);
    }
  } while (rc == LIBEVDEV_READ_STATUS_SUCCESS ||
           rc == LIBEVDEV_READ_STATUS_SYNC);
}

EvdevAudioJackObserver::EvdevAudioJackObserver(
    mojo::PendingRemote<mojom::AudioJackObserver> observer)
    : observer_(std::move(observer)) {}

bool EvdevAudioJackObserver::IsTarget(LibevdevWrapper* dev) {
  return dev->HasEventCode(EV_SW, SW_HEADPHONE_INSERT) &&
         dev->HasEventCode(EV_SW, SW_MICROPHONE_INSERT);
}

void EvdevAudioJackObserver::FireEvent(const input_event& ev,
                                       LibevdevWrapper* dev) {
  if (ev.type != EV_SW) {
    return;
  }

  if (ev.value == 1) {
    if (ev.code == SW_HEADPHONE_INSERT) {
      observer_->OnAdd(mojom::AudioJackEventInfo::DeviceType::kHeadphone);
    }
    if (ev.code == SW_MICROPHONE_INSERT) {
      observer_->OnAdd(mojom::AudioJackEventInfo::DeviceType::kMicrophone);
    }
  } else {
    if (ev.code == SW_HEADPHONE_INSERT) {
      observer_->OnRemove(mojom::AudioJackEventInfo::DeviceType::kHeadphone);
    }
    if (ev.code == SW_MICROPHONE_INSERT) {
      observer_->OnRemove(mojom::AudioJackEventInfo::DeviceType::kMicrophone);
    }
  }
}

void EvdevAudioJackObserver::InitializationFail(
    uint32_t custom_reason, const std::string& description) {
  observer_.ResetWithReason(custom_reason, description);
}

void EvdevAudioJackObserver::ReportProperties(LibevdevWrapper* dev) {}

EvdevTouchpadObserver::EvdevTouchpadObserver(
    mojo::PendingRemote<mojom::TouchpadObserver> observer)
    : observer_(std::move(observer)) {}

bool EvdevTouchpadObserver::IsTarget(LibevdevWrapper* dev) {
  // - Typical pointer devices: touchpads, tablets, mice.
  // - Typical non-direct devices: touchpads, mice.
  // - Check for event type EV_ABS to exclude mice, which report movement with
  //   REL_{X,Y} instead of ABS_{X,Y}.
  return dev->HasProperty(INPUT_PROP_POINTER) &&
         !dev->HasProperty(INPUT_PROP_DIRECT) && dev->HasEventType(EV_ABS);
}

void EvdevTouchpadObserver::FireEvent(const input_event& ev,
                                      LibevdevWrapper* dev) {
  if (ev.type == EV_SYN && ev.code == SYN_REPORT) {
    observer_->OnTouch(mojom::TouchpadTouchEvent::New(FetchTouchPoints(dev)));
  } else if (ev.type == EV_KEY) {
    auto button = EventCodeToInputTouchButton(ev.code);
    if (button.has_value()) {
      bool pressed = (ev.value != 0);
      observer_->OnButton(
          mojom::TouchpadButtonEvent::New(button.value(), pressed));
    }
  }
}

void EvdevTouchpadObserver::InitializationFail(uint32_t custom_reason,
                                               const std::string& description) {
  observer_.ResetWithReason(custom_reason, description);
}

void EvdevTouchpadObserver::ReportProperties(LibevdevWrapper* dev) {
  auto connected_event = mojom::TouchpadConnectedEvent::New();
  connected_event->max_x = std::max(dev->GetAbsMaximum(ABS_X), 0);
  connected_event->max_y = std::max(dev->GetAbsMaximum(ABS_Y), 0);
  connected_event->max_pressure =
      std::max(dev->GetAbsMaximum(ABS_MT_PRESSURE), 0);
  if (dev->HasEventType(EV_KEY)) {
    std::vector<unsigned int> codes{BTN_LEFT, BTN_MIDDLE, BTN_RIGHT};
    for (const auto code : codes) {
      if (dev->HasEventCode(EV_KEY, code)) {
        auto button = EventCodeToInputTouchButton(code);
        if (button.has_value()) {
          connected_event->buttons.push_back(button.value());
        }
      }
    }
  }
  observer_->OnConnected(std::move(connected_event));
}

EvdevTouchscreenObserver::EvdevTouchscreenObserver(
    mojo::PendingRemote<mojom::TouchscreenObserver> observer)
    : observer_(std::move(observer)) {}

bool EvdevTouchscreenObserver::IsTarget(LibevdevWrapper* dev) {
  // - Typical non-pointer devices: touchscreens.
  // - Typical direct devices: touchscreens, drawing tablets.
  // - Use ABS_MT_TRACKING_ID to filter out stylus.
  return !dev->HasProperty(INPUT_PROP_POINTER) &&
         dev->HasProperty(INPUT_PROP_DIRECT) &&
         dev->HasEventCode(EV_ABS, ABS_MT_TRACKING_ID);
}

void EvdevTouchscreenObserver::FireEvent(const input_event& ev,
                                         LibevdevWrapper* dev) {
  if (ev.type == EV_SYN && ev.code == SYN_REPORT) {
    observer_->OnTouch(
        mojom::TouchscreenTouchEvent::New(FetchTouchPoints(dev)));
  }
}

void EvdevTouchscreenObserver::InitializationFail(
    uint32_t custom_reason, const std::string& description) {
  observer_.ResetWithReason(custom_reason, description);
}

void EvdevTouchscreenObserver::ReportProperties(LibevdevWrapper* dev) {
  auto connected_event = mojom::TouchscreenConnectedEvent::New();
  connected_event->max_x = std::max(dev->GetAbsMaximum(ABS_X), 0);
  connected_event->max_y = std::max(dev->GetAbsMaximum(ABS_Y), 0);
  connected_event->max_pressure =
      std::max(dev->GetAbsMaximum(ABS_MT_PRESSURE), 0);
  observer_->OnConnected(std::move(connected_event));
}

EvdevStylusGarageObserver::EvdevStylusGarageObserver(
    mojo::PendingRemote<mojom::StylusGarageObserver> observer)
    : observer_(std::move(observer)) {}

bool EvdevStylusGarageObserver::IsTarget(LibevdevWrapper* dev) {
  return dev->HasEventCode(EV_SW, SW_PEN_INSERTED);
}

void EvdevStylusGarageObserver::FireEvent(const input_event& ev,
                                          LibevdevWrapper* dev) {
  if (ev.type != EV_SW) {
    return;
  }

  if (ev.code == SW_PEN_INSERTED) {
    if (ev.value == 1) {
      observer_->OnInsert();
    } else {
      observer_->OnRemove();
    }
  }
}

void EvdevStylusGarageObserver::InitializationFail(
    uint32_t custom_reason, const std::string& description) {
  observer_.ResetWithReason(custom_reason, description);
}

void EvdevStylusGarageObserver::ReportProperties(LibevdevWrapper* dev) {}

EvdevStylusObserver::EvdevStylusObserver(
    mojo::PendingRemote<mojom::StylusObserver> observer)
    : observer_(std::move(observer)) {}

bool EvdevStylusObserver::IsTarget(LibevdevWrapper* dev) {
  // - Typical non-pointer devices: touchscreens.
  // - Typical direct devices: touchscreens, drawing tablets.
  // - Use ABS_MT_TRACKING_ID to filter out touchscreen.
  return !dev->HasProperty(INPUT_PROP_POINTER) &&
         dev->HasProperty(INPUT_PROP_DIRECT) &&
         !dev->HasEventCode(EV_ABS, ABS_MT_TRACKING_ID);
}

void EvdevStylusObserver::FireEvent(const input_event& ev,
                                    LibevdevWrapper* dev) {
  if (ev.type == EV_SYN && ev.code == SYN_REPORT) {
    bool is_stylus_in_contact = dev->GetEventValue(EV_KEY, BTN_TOUCH);
    if (is_stylus_in_contact) {
      auto point_info = mojom::StylusTouchPointInfo::New();
      point_info->x = dev->GetEventValue(EV_ABS, ABS_X);
      point_info->y = dev->GetEventValue(EV_ABS, ABS_Y);
      point_info->pressure =
          mojom::NullableUint32::New(dev->GetEventValue(EV_ABS, ABS_PRESSURE));

      observer_->OnTouch(mojom::StylusTouchEvent::New(std::move(point_info)));
      last_event_has_touch_point_ = true;
    } else {
      // Don't repeatedly report events without the touch point.
      if (last_event_has_touch_point_) {
        observer_->OnTouch(mojom::StylusTouchEvent::New());
        last_event_has_touch_point_ = false;
      }
    }
  }
}

void EvdevStylusObserver::InitializationFail(uint32_t custom_reason,
                                             const std::string& description) {
  observer_.ResetWithReason(custom_reason, description);
}

void EvdevStylusObserver::ReportProperties(LibevdevWrapper* dev) {
  auto connected_event = mojom::StylusConnectedEvent::New();
  connected_event->max_x = std::max(dev->GetAbsMaximum(ABS_X), 0);
  connected_event->max_y = std::max(dev->GetAbsMaximum(ABS_Y), 0);
  connected_event->max_pressure = std::max(dev->GetAbsMaximum(ABS_PRESSURE), 0);
  observer_->OnConnected(std::move(connected_event));
}

EvdevPowerButtonObserver::EvdevPowerButtonObserver(
    mojo::PendingRemote<mojom::PowerButtonObserver> observer)
    : observer_(std::move(observer)) {}

bool EvdevPowerButtonObserver::IsTarget(LibevdevWrapper* dev) {
  // Only internal power button is desired. Filter out USB devices to exclude
  // external power buttons.
  return dev->HasEventCode(EV_KEY, KEY_POWER) && dev->GetIdBustype() != BUS_USB;
}

void EvdevPowerButtonObserver::FireEvent(const input_event& ev,
                                         LibevdevWrapper* dev) {
  if (ev.type == EV_KEY && ev.code == KEY_POWER) {
    if (ev.value == 0) {
      observer_->OnEvent(mojom::PowerButtonObserver::ButtonState::kUp);
    } else if (ev.value == 1) {
      observer_->OnEvent(mojom::PowerButtonObserver::ButtonState::kDown);
    } else if (ev.value == 2) {
      observer_->OnEvent(mojom::PowerButtonObserver::ButtonState::kRepeat);
    }
  }
}

void EvdevPowerButtonObserver::InitializationFail(
    uint32_t custom_reason, const std::string& description) {
  observer_.ResetWithReason(custom_reason, description);
}

void EvdevPowerButtonObserver::ReportProperties(LibevdevWrapper* dev) {}

EvdevVolumeButtonObserver::EvdevVolumeButtonObserver(
    mojo::PendingRemote<mojom::VolumeButtonObserver> observer)
    : observer_(std::move(observer)) {}

bool EvdevVolumeButtonObserver::IsTarget(LibevdevWrapper* dev) {
  return dev->HasEventCode(EV_KEY, KEY_VOLUMEDOWN) &&
         dev->HasEventCode(EV_KEY, KEY_VOLUMEUP);
}

void EvdevVolumeButtonObserver::FireEvent(const input_event& ev,
                                          LibevdevWrapper* dev) {
  if (ev.type != EV_KEY) {
    return;
  }

  mojom::VolumeButtonObserver::Button button;
  if (ev.code == KEY_VOLUMEUP) {
    button = mojom::VolumeButtonObserver::Button::kVolumeUp;
  } else if (ev.code == KEY_VOLUMEDOWN) {
    button = mojom::VolumeButtonObserver::Button::kVolumeDown;
  } else {
    return;
  }

  mojom::VolumeButtonObserver::ButtonState button_state;
  if (ev.value == 0) {
    button_state = mojom::VolumeButtonObserver::ButtonState::kUp;
  } else if (ev.value == 1) {
    button_state = mojom::VolumeButtonObserver::ButtonState::kDown;
  } else if (ev.value == 2) {
    button_state = mojom::VolumeButtonObserver::ButtonState::kRepeat;
  } else {
    return;
  }

  observer_->OnEvent(button, button_state);
}

void EvdevVolumeButtonObserver::InitializationFail(
    uint32_t custom_reason, const std::string& description) {
  observer_.ResetWithReason(custom_reason, description);
}

void EvdevVolumeButtonObserver::ReportProperties(LibevdevWrapper* dev) {}

}  // namespace diagnostics
