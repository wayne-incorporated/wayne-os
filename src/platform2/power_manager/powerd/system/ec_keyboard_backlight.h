// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_EC_KEYBOARD_BACKLIGHT_H_
#define POWER_MANAGER_POWERD_SYSTEM_EC_KEYBOARD_BACKLIGHT_H_

#include <memory>
#include <string>

#include <base/time/time.h>
#include <base/timer/timer.h>
#include <libec/ec_command.h>
#include <libec/ec_usb_endpoint.h>
#include <libec/pwm_command.h>

#include "power_manager/powerd/system/internal_backlight.h"

namespace power_manager::system {

class EcKeyboardBacklight : public InternalBacklight {
 public:
  static const int kMaxBrightnessLevel;

  EcKeyboardBacklight();
  explicit EcKeyboardBacklight(
      std::unique_ptr<ec::GetKeyboardBacklightCommand> get_cmd);
  EcKeyboardBacklight(const EcKeyboardBacklight&) = delete;
  EcKeyboardBacklight& operator=(const EcKeyboardBacklight&) = delete;

  ~EcKeyboardBacklight() override = default;

  bool Init(ec::EcUsbEndpointInterface* uep);
  bool SetBrightnessLevel(int64_t level, base::TimeDelta interval) override;

 private:
  bool WriteBrightness(int64_t new_level) override;
  ec::EcUsbEndpointInterface* usb_endpoint_ = nullptr;
  std::unique_ptr<ec::GetKeyboardBacklightCommand> get_cmd_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_EC_KEYBOARD_BACKLIGHT_H_
