// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <stdio.h>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <brillo/flag_helper.h>

namespace {

constexpr struct input_event kSync = {
    .type = EV_SYN, .code = SYN_REPORT, .value = 0};

constexpr int kBitsPerInt = sizeof(uint32_t) * 8;
constexpr int kMaxInputDev = 256;
// When creating an input device, time delay before send out events to it.
constexpr base::TimeDelta kUinputDevInjectDelay = base::Seconds(1);
constexpr char kUinputDev[] = "/dev/uinput";
const int kMaxBit = std::max(std::max(EV_MAX, KEY_MAX), SW_MAX);
const int kMaxInt = (kMaxBit - 1) / kBitsPerInt + 1;

bool TestBit(const uint32_t bitmask[], int bit) {
  return ((bitmask[bit / kBitsPerInt] >> (bit % kBitsPerInt)) & 1);
}

bool HasEventBit(int fd, int event_type, int bit) {
  uint32_t bitmask[kMaxInt];
  memset(bitmask, 0, sizeof(bitmask));
  if (ioctl(fd, EVIOCGBIT(event_type, sizeof(bitmask)), bitmask) < 0)
    return false;
  return TestBit(bitmask, bit);
}

void LogErrorExit(const std::string& message) {
  LOG(ERROR) << message;
  exit(1);
}

// CreateEvent return a correctly filled input_event. It aborts on
// invalid |code| or |value|.
// |code|: "tablet", "lid"
// |value|: 0, 1
struct input_event CreateEvent(const std::string& code, int32_t value) {
  struct input_event event;
  event.type = EV_SW;
  if (code == "tablet")
    event.code = SW_TABLET_MODE;
  else if (code == "lid")
    event.code = SW_LID;
  else
    LogErrorExit("--code=<tablet|lid>");
  if (value != 0 && value != 1)
    LogErrorExit("--value=<0|1>");
  event.value = value;
  return event;
}

// Create an input device which supports given event |type|
// and |code| with uinput interface. It will be alive for
// |lifetime|.
base::ScopedFD CreateDevice(int type, int code, base::TimeDelta lifetime) {
  base::ScopedFD fd(open(kUinputDev, O_RDWR | O_CLOEXEC));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to open " << kUinputDev;
    return base::ScopedFD();
  }
  int ui_set_type_bit;
  switch (type) {
    case EV_SW:
      ui_set_type_bit = UI_SET_SWBIT;
      break;
    case EV_KEY:
      ui_set_type_bit = UI_SET_KEYBIT;
      break;
    default:
      LOG(FATAL) << "not handled type: " << type;
  }

  if (TEMP_FAILURE_RETRY(ioctl(fd.get(), UI_SET_EVBIT, type))) {
    PLOG(ERROR) << "ioctl ui_set_evbit";
    return base::ScopedFD();
  }
  if (TEMP_FAILURE_RETRY(ioctl(fd.get(), ui_set_type_bit, code))) {
    PLOG(ERROR) << "ioctl ui_set_type_bit";
    return base::ScopedFD();
  }
  struct uinput_user_dev dev;
  memset(&dev, 0, sizeof(dev));
  snprintf(dev.name, sizeof(dev.name), "inject powerd");
  TEMP_FAILURE_RETRY(write(fd.get(), &dev, sizeof(dev)));
  if (TEMP_FAILURE_RETRY(ioctl(fd.get(), UI_DEV_CREATE))) {
    PLOG(ERROR) << "ioctl ui_dev_create";
    return base::ScopedFD();
  }
  // Create a child process to hold this fd to keep created
  // device alive.
  if (fork() == 0) {
    setsid();
    sleep(lifetime.InSeconds());
    exit(0);
  }
  // Give powerd time to open new created device.
  sleep(kUinputDevInjectDelay.InSeconds());
  return fd;
}

// Find the event device which supports said |type| and |code| and
// return opened file descriptor to it.
base::ScopedFD OpenDevice(int type, int code) {
  base::ScopedFD fd;
  for (int i = 0; i < kMaxInputDev; ++i) {
    fd.reset(open(base::StringPrintf("/dev/input/event%d", i).c_str(),
                  O_RDWR | O_CLOEXEC));
    if (!fd.is_valid())
      break;
    if (HasEventBit(fd.get(), 0, type) && HasEventBit(fd.get(), type, code))
      break;
  }
  return fd;
}

void InjectEvent(const struct input_event& event,
                 bool create_dev,
                 base::TimeDelta lifetime) {
  base::ScopedFD fd = OpenDevice(event.type, event.code);
  if (!fd.is_valid()) {
    if (!create_dev) {
      LogErrorExit("No supported input device, try --create_dev");
    }
    fd = CreateDevice(event.type, event.code, lifetime);
    if (!fd.is_valid()) {
      LogErrorExit("Failed to create device");
    }
  }

  TEMP_FAILURE_RETRY(write(fd.get(), &event, sizeof(event)));
  TEMP_FAILURE_RETRY(write(fd.get(), &kSync, sizeof(kSync)));
}

}  // namespace

int main(int argc, char* argv[]) {
  DEFINE_string(code, "", "Input event type to inject (one of tablet, lid)");
  DEFINE_int32(value, -1, "Input event value to inject (0 is off, 1 is on)");
  DEFINE_bool(create_dev, false,
              "Create device if no device supports wanted input event");
  DEFINE_int32(dev_lifetime, 300, "Lifetime (in seconds) of created device");

  brillo::FlagHelper::Init(argc, argv, "Inject input events to powerd.\n");

  struct input_event event = CreateEvent(FLAGS_code, FLAGS_value);

  InjectEvent(event, FLAGS_create_dev, base::Seconds(FLAGS_dev_lifetime));
  return 0;
}
