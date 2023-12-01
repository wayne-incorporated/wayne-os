// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_LED_CONTROL_COMMAND_H_
#define LIBEC_LED_CONTROL_COMMAND_H_

#include <array>

#include <base/logging.h>
#include <brillo/brillo_export.h>

#include "libec/ec_command.h"

namespace ec {

class LedControlCommand : public EcCommand<struct ec_params_led_control,
                                           struct ec_response_led_control> {
 public:
  LedControlCommand();
  ~LedControlCommand() override = default;
};

// Command to query the LED capability.
class BRILLO_EXPORT LedControlQueryCommand : public LedControlCommand {
 public:
  explicit LedControlQueryCommand(enum ec_led_id led_id);
  ~LedControlQueryCommand() override = default;

  bool Run(int fd) override;

  // The maximum brightness of each channel. Notice that it is NOT the current
  // brightness but the highest brightness level that can be set.
  std::array<uint8_t, EC_LED_COLOR_COUNT> BrightnessRange() const;

 protected:
  virtual bool EcCommandRun(int fd);

 private:
  std::array<uint8_t, EC_LED_COLOR_COUNT> brightness_range_;
};

// Command to switch LED back to automatic control.
class BRILLO_EXPORT LedControlAutoCommand : public LedControlCommand {
 public:
  explicit LedControlAutoCommand(enum ec_led_id led_id);
  ~LedControlAutoCommand() override = default;
};

// Command to set the LED brightness.
class BRILLO_EXPORT LedControlSetCommand : public LedControlCommand {
 public:
  explicit LedControlSetCommand(
      enum ec_led_id led_id,
      std::array<uint8_t, EC_LED_COLOR_COUNT> brightness);
  ~LedControlSetCommand() override = default;
};

static_assert(!std::is_copy_constructible<LedControlCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<LedControlCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_LED_CONTROL_COMMAND_H_
