// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RGBKBD_KEYBOARD_BACKLIGHT_LOGGER_H_
#define RGBKBD_KEYBOARD_BACKLIGHT_LOGGER_H_

#include <dbus/rgbkbd/dbus-constants.h>
#include <memory>

#include <stdint.h>
#include <string>

#include "base/files/file.h"
#include "rgbkbd/rgb_keyboard.h"

namespace rgbkbd {

class KeyboardBacklightLogger : public RgbKeyboard {
 public:
  KeyboardBacklightLogger(const base::FilePath& path,
                          RgbKeyboardCapabilities capability);
  KeyboardBacklightLogger(const KeyboardBacklightLogger&) = delete;
  KeyboardBacklightLogger& operator=(const KeyboardBacklightLogger&) = delete;
  ~KeyboardBacklightLogger() override = default;

  bool SetKeyColor(uint32_t key, uint8_t r, uint8_t g, uint8_t b) override;
  bool SetAllKeyColors(uint8_t r, uint8_t g, uint8_t b) override;
  RgbKeyboardCapabilities GetRgbKeyboardCapabilities() override;
  void ResetUsbKeyboard() override { reset_called_ = true; }
  void InitializeUsbKeyboard() override { init_called_ = true; }
  // Clears log.
  bool ResetLog();
  bool IsLogEmpty();

  bool init_called() const { return init_called_; }
  bool reset_called() const { return reset_called_; }

 private:
  bool InitializeFile();
  bool WriteLogEntry(const std::string& log);

  std::unique_ptr<base::File> file_;
  base::FilePath log_path_;
  RgbKeyboardCapabilities capabilities_;
  bool init_called_ = false;
  bool reset_called_ = false;
};

}  // namespace rgbkbd

#endif  // RGBKBD_KEYBOARD_BACKLIGHT_LOGGER_H_
