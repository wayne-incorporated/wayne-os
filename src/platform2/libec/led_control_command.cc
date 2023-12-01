// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <string>

#include "libec/led_control_command.h"

namespace ec {

LedControlCommand::LedControlCommand() : EcCommand(EC_CMD_LED_CONTROL, 1) {}

LedControlQueryCommand::LedControlQueryCommand(enum ec_led_id led_id) {
  Req()->led_id = led_id;
  Req()->flags = EC_LED_FLAGS_QUERY;
}

std::array<uint8_t, EC_LED_COLOR_COUNT>
LedControlQueryCommand::BrightnessRange() const {
  return brightness_range_;
}

bool LedControlQueryCommand::Run(int fd) {
  if (!EcCommandRun(fd)) {
    return false;
  }

  std::copy(Resp()->brightness_range,
            Resp()->brightness_range + EC_LED_COLOR_COUNT,
            std::begin(brightness_range_));

  return true;
}

bool LedControlQueryCommand::EcCommandRun(int fd) {
  return EcCommand::Run(fd);
}

LedControlAutoCommand::LedControlAutoCommand(enum ec_led_id led_id) {
  Req()->led_id = led_id;
  Req()->flags = EC_LED_FLAGS_AUTO;
}

LedControlSetCommand::LedControlSetCommand(
    enum ec_led_id led_id, std::array<uint8_t, EC_LED_COLOR_COUNT> brightness) {
  Req()->led_id = led_id;
  Req()->flags = 0;
  std::copy(brightness.begin(), brightness.end(), Req()->brightness);
}

}  // namespace ec
