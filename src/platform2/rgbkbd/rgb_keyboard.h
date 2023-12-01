// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RGBKBD_RGB_KEYBOARD_H_
#define RGBKBD_RGB_KEYBOARD_H_

#include <dbus/rgbkbd/dbus-constants.h>

namespace rgbkbd {

// Base interface class that exposes the API to interact with the keyboard's RGB
// service.
class RgbKeyboard {
 public:
  RgbKeyboard() = default;
  virtual ~RgbKeyboard() = default;

  virtual bool SetKeyColor(uint32_t key, uint8_t r, uint8_t g, uint8_t b) = 0;
  virtual bool SetAllKeyColors(uint8_t r, uint8_t g, uint8_t b) = 0;
  virtual RgbKeyboardCapabilities GetRgbKeyboardCapabilities() = 0;
  virtual void ResetUsbKeyboard() = 0;
  virtual void InitializeUsbKeyboard() = 0;
};

}  // namespace rgbkbd

#endif  // RGBKBD_RGB_KEYBOARD_H_
