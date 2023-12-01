// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/ec_keyboard_backlight.h"

#include <cmath>
#include <fcntl.h>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <libec/ec_command.h>
#include <libec/pwm_command.h>

namespace power_manager::system {

const int EcKeyboardBacklight::kMaxBrightnessLevel = 100;

EcKeyboardBacklight::EcKeyboardBacklight()
    : get_cmd_(std::make_unique<ec::GetKeyboardBacklightCommand>()) {}

EcKeyboardBacklight::EcKeyboardBacklight(
    std::unique_ptr<ec::GetKeyboardBacklightCommand> get_cmd)
    : get_cmd_(std::move(get_cmd)) {}

bool EcKeyboardBacklight::Init(ec::EcUsbEndpointInterface* uep) {
  usb_endpoint_ = uep;
  max_brightness_level_ = kMaxBrightnessLevel;

  if (usb_endpoint_) {
    LOG(INFO) << "Sending GET_KEYBOARD_BACKLIGHT over USB";
    if (!get_cmd_->Run(*usb_endpoint_)) {
      LOG(INFO) << "Failed to read keyboard backlight brightness over USB";
      return false;
    }
  } else {
    LOG(INFO) << "Sending GET_KEYBOARD_BACKLIGHT to over " << ec::kCrosEcPath;
    base::ScopedFD ec_fd = base::ScopedFD(open(ec::kCrosEcPath, O_RDWR));
    if (!ec_fd.is_valid()) {
      LOG(ERROR) << "Failed to open " << ec::kCrosEcPath;
      return false;
    }
    if (!get_cmd_->Run(ec_fd.get())) {
      LOG(INFO) << "Failed to read keyboard backlight brightness from EC";
      return false;
    }
  }

  current_brightness_level_ = get_cmd_->Brightness();
  return true;
}

bool EcKeyboardBacklight::SetBrightnessLevel(int64_t level,
                                             base::TimeDelta interval) {
  return DoSetBrightnessLevel(level, interval);
}

bool EcKeyboardBacklight::WriteBrightness(int64_t new_level) {
  // TODO(b/265492733): Move to EcCommandFactory to allow mocking for unittests.
  ec::SetKeyboardBacklightCommand cmd(new_level);
  if (usb_endpoint_) {
    if (!cmd.Run(*usb_endpoint_)) {
      LOG(INFO)
          << "Failed to read keyboard backlight brightness from MCU over USB";
      return false;
    }
  } else {
    base::ScopedFD ec_fd = base::ScopedFD(open(ec::kCrosEcPath, O_RDWR));
    if (!ec_fd.is_valid()) {
      PLOG(ERROR) << "Failed to open " << ec::kCrosEcPath;
      return false;
    }
    if (!cmd.Run(ec_fd.get())) {
      LOG(INFO) << "Failed to read keyboard backlight brightness from EC";
      return false;
    }
  }

  current_brightness_level_ = new_level;
  return true;
}

}  // namespace power_manager::system
