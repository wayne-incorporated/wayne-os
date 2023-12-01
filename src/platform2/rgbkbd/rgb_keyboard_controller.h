// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RGBKBD_RGB_KEYBOARD_CONTROLLER_H_
#define RGBKBD_RGB_KEYBOARD_CONTROLLER_H_

#include <cstdint>

#include "dbus/rgbkbd/dbus-constants.h"
#include "rgbkbd/rgb_keyboard.h"

namespace rgbkbd {

class RgbKeyboardController {
 public:
  RgbKeyboardController() = default;
  virtual ~RgbKeyboardController() = default;

  virtual uint32_t GetRgbKeyboardCapabilities() = 0;
  virtual void SetCapsLockState(bool enabled) = 0;
  virtual void SetStaticBackgroundColor(uint8_t r, uint8_t g, uint8_t b) = 0;
  virtual void SetStaticZoneColor(int zone_idx,
                                  uint8_t r,
                                  uint8_t g,
                                  uint8_t b) = 0;
  virtual void SetRainbowMode() = 0;
  virtual void SetAnimationMode(RgbAnimationMode mode) = 0;
  virtual void SetKeyboardClient(RgbKeyboard* keyboard) = 0;
  virtual void ReinitializeOnDeviceReconnected() = 0;
};

}  // namespace rgbkbd

#endif  // RGBKBD_RGB_KEYBOARD_CONTROLLER_H_
