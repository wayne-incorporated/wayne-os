// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/uinput_device.h"

#include <fcntl.h>
#include <linux/uinput.h>
#include <sys/ioctl.h>

#include <algorithm>
#include <cstring>

#include <base/check.h>
#include <base/logging.h>

namespace biod {

namespace {
// When creating a new uinput device, you must specify these parameters like
// with an actual, physical device. These are sane, safe values that we use
// when creating a uinput device. Note that powerd uses this name to identify
// Chrome OS fingerprint devices.
constexpr char kFpInputDeviceName[] = "cros_fp_input";
// This is the file handle on disk that you use to control the uinput module.
constexpr char kUinputControlPath[] = "/dev/uinput";

constexpr int kDummyProductID = 0xffff;
constexpr int kGoogleVendorID = 0x18d1;
constexpr int kVersionNumber = 1;
}  // namespace

UinputDevice::UinputDevice() {
  uinput_fd_ = base::ScopedFD(-1);
}

UinputDevice::~UinputDevice() {
  // Tell the OS to destroy the uinput device as this object is destructed.
  if (uinput_fd_.is_valid()) {
    int error = TEMP_FAILURE_RETRY(ioctl(uinput_fd_.get(), UI_DEV_DESTROY));
    if (error == -1) {
      PLOG(ERROR) << "Unable to destroy uinput device.";
    }
  }
}

bool UinputDevice::Init() {
  // Open a control file descriptor for creating a new uinput device.
  // This file descriptor is used with ioctls to configure the device and
  // receive the outgoing event information.
  if (uinput_fd_.is_valid()) {
    LOG(ERROR) << "Control FD already opened! (" << uinput_fd_.get() << ").";
    return false;
  }

  uinput_fd_ = base::ScopedFD(
      TEMP_FAILURE_RETRY(open(kUinputControlPath, O_WRONLY | O_NONBLOCK)));
  if (!uinput_fd_.is_valid()) {
    PLOG(ERROR) << "Unable to open " << kUinputControlPath << ".";
    return false;
  }
  LOG(INFO) << "Uinput control file descriptor opened (" << uinput_fd_.get()
            << ").";

  // Tell the kernel that this uinput device will report events of a
  // type |EV_KEY|. Individual event codes must still be
  // enabled individually, but their overarching types need to be enabled
  // first, which is done here.
  int error = TEMP_FAILURE_RETRY(ioctl(uinput_fd_.get(), UI_SET_EVBIT, EV_KEY));
  if (error == -1) {
    PLOG(ERROR) << "Unable to enable event type 0x" << std::hex << EV_KEY
                << ".";
    return false;
  }
  LOG(INFO) << "Enabled events of type 0x" << std::hex << EV_KEY << ".";

  // Tell the kernel that this uinput device will report |KEY_WAKEUP|
  // key event.
  error =
      TEMP_FAILURE_RETRY(ioctl(uinput_fd_.get(), UI_SET_KEYBIT, KEY_WAKEUP));
  if (error == -1) {
    PLOG(ERROR) << "Unable to enable EV_KEY 0x" << std::hex << KEY_WAKEUP
                << " events.";
    return false;
  }
  LOG(INFO) << "Enabled EV_KEY 0x" << std::hex << KEY_WAKEUP << " events.";

  if (!FinalizeUinputCreation()) {
    return false;
  }

  return true;
}

bool UinputDevice::SendEvent(int value) const {
  // Send an input event to the kernel through this uinput device.
  struct input_event ev = {.time = base::Time::Now().ToTimeVal(),
                           .type = EV_KEY,
                           .code = KEY_WAKEUP,
                           .value = value};

  int bytes_written =
      TEMP_FAILURE_RETRY(write(uinput_fd_.get(), &ev, sizeof(ev)));
  if (bytes_written != sizeof(ev)) {
    LOG(ERROR) << "Failed to write() when sending an event. (" << bytes_written
               << ").";
    return false;
  }
  return true;
}

bool UinputDevice::FinalizeUinputCreation() const {
  struct uinput_setup device_info = {};
  DCHECK(strlen(kFpInputDeviceName) < UINPUT_MAX_NAME_SIZE);
  std::copy(kFpInputDeviceName, kFpInputDeviceName + strlen(kFpInputDeviceName),
            device_info.name);
  device_info.id = {.bustype = BUS_USB,
                    .vendor = kGoogleVendorID,
                    .product = kDummyProductID,
                    .version = kVersionNumber};
  int error =
      TEMP_FAILURE_RETRY(ioctl(uinput_fd_.get(), UI_DEV_SETUP, &device_info));
  if (error == -1) {
    PLOG(ERROR) << "uinput device setup ioctl failed.";
    return false;
  }

  // Finally request that a new uinput device is created to those specs.
  // After this step the device should be fully functional and ready to
  // send events.
  error = TEMP_FAILURE_RETRY(ioctl(uinput_fd_.get(), UI_DEV_CREATE));
  if (error == -1) {
    PLOG(ERROR) << "uinput device creation ioctl failed.";
    return false;
  }

  LOG(INFO) << "Successfully finalized uinput device creation.";
  return true;
}

}  // namespace biod
