// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/event_device.h"

#include <utility>

#include <fcntl.h>
#include <linux/input.h>

#include <base/check.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>

#include "power_manager/common/power_constants.h"
#include "power_manager/common/tracing.h"

// Helper macros for accessing the bitfields returned by the kernel interface,
// compare with include/linux/bitops.h.
#define BITS_PER_LONG (sizeof(long) * 8)  // NOLINT(runtime/int)
#define BITS_TO_LONGS(bits) (((bits)-1) / BITS_PER_LONG + 1)
#define BITMASK_GET_BIT(bitmask, bit) \
  ((bitmask[bit / BITS_PER_LONG] >> (bit % BITS_PER_LONG)) & 1)

#define MAX(a, b) ((a) > (b) ? (a) : (b))

namespace power_manager::system {

namespace {
// C++14's <algorithm> could do std::max(EV_MAX, KEY_MAX, SW_MAX);
static constexpr int kMaxBit = MAX(MAX(EV_MAX, KEY_MAX), SW_MAX);
}  // namespace

EventDevice::EventDevice(int fd, const base::FilePath& path)
    : fd_(fd), path_(path) {}

EventDevice::~EventDevice() {
  fd_watcher_.reset();
  // ENODEV is expected if the device was just unplugged.
  if (close(fd_) != 0 && errno != ENODEV)
    PLOG(ERROR) << "Unable to close FD " << fd_;
}

std::string EventDevice::GetDebugName() {
  return path_.value();
}

std::string EventDevice::GetPhysPath() {
  char phys[256] = "";

  if (TEMP_FAILURE_RETRY(ioctl(fd_, EVIOCGPHYS(sizeof(phys)), phys)) < 0 &&
      errno != ENOENT)
    PLOG(ERROR) << "Could not get topo phys path of " << path_.value();

  return phys;
}

std::string EventDevice::GetName() {
  char name[256] = {0};

  if (TEMP_FAILURE_RETRY(ioctl(fd_, EVIOCGNAME(sizeof(name) - 1), name)) < 0)
    PLOG(ERROR) << "Could not get name of " << path_.value();

  return name;
}

bool EventDevice::IsCrosFp() {
  return GetName() == kCrosFpInputDevName;
}

bool EventDevice::IsLidSwitch() {
  return HasEventBit(0, EV_SW) && HasEventBit(EV_SW, SW_LID);
}

bool EventDevice::IsTabletModeSwitch() {
  return HasEventBit(0, EV_SW) && HasEventBit(EV_SW, SW_TABLET_MODE);
}

bool EventDevice::IsPowerButton() {
  return HasEventBit(0, EV_KEY) && HasEventBit(EV_KEY, KEY_POWER);
}

bool EventDevice::HoverSupported() {
  // Multitouch hover uses just the ABS_MT_DISTANCE event in addition to
  // the normal multi-touch events.
  if (HasEventBit(0, EV_ABS) && HasEventBit(EV_ABS, ABS_MT_DISTANCE))
    return true;

  // Simple single-touch hover presence-only detection uses 3 events:
  // ABS_DISTANCE, BTN_TOUCH, and BTN_TOOL_FINGER.
  if (HasEventBit(0, EV_ABS) && HasEventBit(EV_ABS, ABS_DISTANCE) &&
      HasEventBit(0, EV_KEY) && HasEventBit(EV_KEY, BTN_TOUCH) &&
      HasEventBit(EV_KEY, BTN_TOOL_FINGER))
    return true;

  return false;
}

bool EventDevice::HasLeftButton() {
  return HasEventBit(0, EV_KEY) && HasEventBit(EV_KEY, BTN_LEFT);
}

LidState EventDevice::GetInitialLidState() {
  CHECK(!fd_watcher_) << "GetInitialLidState called after WatchForEvents";
  return GetSwitchBit(SW_LID) ? LidState::CLOSED : LidState::OPEN;
}

TabletMode EventDevice::GetInitialTabletMode() {
  CHECK(!fd_watcher_) << "GetInitialTabletMode called after WatchForEvents";
  return GetSwitchBit(SW_TABLET_MODE) ? TabletMode::ON : TabletMode::OFF;
}

bool EventDevice::HasEventBit(int event_type, int bit) {
  DCHECK(bit <= kMaxBit);

  // bitmask needs to hold kMaxBit+1 bits
  unsigned long bitmask[BITS_TO_LONGS(kMaxBit + 1)];  // NOLINT(runtime/int)
  memset(bitmask, 0, sizeof(bitmask));
  if (TEMP_FAILURE_RETRY(
          ioctl(fd_, EVIOCGBIT(event_type, sizeof(bitmask)), bitmask)) < 0) {
    PLOG(ERROR) << "EVIOCGBIT failed for " << path_.value();
    return false;
  }
  return BITMASK_GET_BIT(bitmask, bit);
}

bool EventDevice::GetSwitchBit(int bit) {
  DCHECK(bit <= kMaxBit);

  // bitmask needs to hold SW_MAX+1 bits
  unsigned long bitmask[BITS_TO_LONGS(SW_MAX + 1)];  // NOLINT(runtime/int)
  memset(bitmask, 0, sizeof(bitmask));
  if (TEMP_FAILURE_RETRY(ioctl(fd_, EVIOCGSW(sizeof(bitmask)), bitmask)) < 0) {
    PLOG(ERROR) << "EVIOCGBIT failed for " << path_.value();
    return false;
  }
  return BITMASK_GET_BIT(bitmask, bit);
}

EventDevice::ReadResult EventDevice::ReadEvents(
    std::vector<input_event>* events_out) {
  TRACE_EVENT("power", "EventDevice::ReadEvents", "fd", fd_, "path",
              path_.value());
  DCHECK(events_out);
  events_out->clear();

  struct input_event events[64];
  ssize_t read_size = HANDLE_EINTR(read(fd_, events, sizeof(events)));
  if (read_size < 0) {
    // ENODEV is expected if the device was just unplugged.
    if (errno == ENODEV) {
      return ReadResult::kNoDevice;
    }
    if (errno != EAGAIN && errno != EWOULDBLOCK)
      PLOG(ERROR) << "Reading events from " << path_.value() << " failed";
    return ReadResult::kFailure;
  } else if (read_size == 0) {
    LOG(ERROR) << "Read returned 0 when reading events from " << path_.value();
    return ReadResult::kFailure;
  }

  const size_t num_events = read_size / sizeof(struct input_event);
  if (read_size % sizeof(struct input_event)) {
    LOG(ERROR) << "Read " << read_size << " byte(s) while expecting "
               << sizeof(struct input_event) << "-byte events";
    return ReadResult::kFailure;
  }

  events_out->reserve(num_events);
  for (size_t i = 0; i < num_events; ++i)
    events_out->push_back(events[i]);
  return ReadResult::kSuccess;
}

void EventDevice::WatchForEvents(const base::RepeatingClosure& new_events_cb) {
  // Annotate received events with a trace event.
  auto callback = base::BindRepeating(
      [](const base::RepeatingClosure& callback, int fd,
         const base::FilePath& path) {
        TRACE_EVENT("power", "EventDevice::OnEvent", "fd", fd, "path",
                    path.value());
        callback.Run();
      },
      new_events_cb, fd_, std::ref(path_));
  fd_watcher_ =
      base::FileDescriptorWatcher::WatchReadable(fd_, std::move(callback));
}

std::shared_ptr<EventDeviceInterface> EventDeviceFactory::Open(
    const base::FilePath& path) {
  int fd = HANDLE_EINTR(open(path.value().c_str(), O_RDONLY | O_NONBLOCK));
  if (fd < 0) {
    PLOG(ERROR) << "open() failed for " << path.value();
    return std::shared_ptr<EventDeviceInterface>();
  }
  return std::shared_ptr<EventDeviceInterface>(new EventDevice(fd, path));
}

}  // namespace power_manager::system
