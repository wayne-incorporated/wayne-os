// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_PWM_COMMAND_H_
#define LIBEC_PWM_COMMAND_H_

#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT SetKeyboardBacklightCommand
    : public EcCommand<struct ec_params_pwm_set_keyboard_backlight,
                       EmptyParam> {
 public:
  explicit SetKeyboardBacklightCommand(uint8_t percent)
      : EcCommand(EC_CMD_PWM_SET_KEYBOARD_BACKLIGHT, 0) {
    Req()->percent = percent;
  }
  ~SetKeyboardBacklightCommand() override = default;
};

static_assert(!std::is_copy_constructible<SetKeyboardBacklightCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<SetKeyboardBacklightCommand>::value,
              "EcCommands are not copy-assignable by default");

class BRILLO_EXPORT GetKeyboardBacklightCommand
    : public EcCommand<EmptyParam,
                       struct ec_response_pwm_get_keyboard_backlight> {
 public:
  GetKeyboardBacklightCommand()
      : EcCommand(EC_CMD_PWM_GET_KEYBOARD_BACKLIGHT, 0) {}
  ~GetKeyboardBacklightCommand() override = default;
  virtual uint8_t Brightness() const { return Resp()->percent; }
};

static_assert(!std::is_copy_constructible<GetKeyboardBacklightCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<GetKeyboardBacklightCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_PWM_COMMAND_H_
