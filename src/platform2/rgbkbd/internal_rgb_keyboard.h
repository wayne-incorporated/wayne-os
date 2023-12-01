// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RGBKBD_INTERNAL_RGB_KEYBOARD_H_
#define RGBKBD_INTERNAL_RGB_KEYBOARD_H_

#include <memory>
#include <optional>

#include <base/files/scoped_file.h>
#include <dbus/rgbkbd/dbus-constants.h>
#include <libec/ec_command.h>
#include <libec/ec_usb_endpoint.h>
#include <stdint.h>

#include "rgbkbd/rgb_keyboard.h"

namespace rgbkbd {

class InternalRgbKeyboard : public RgbKeyboard {
 public:
  InternalRgbKeyboard() = default;
  InternalRgbKeyboard(const InternalRgbKeyboard&) = delete;
  InternalRgbKeyboard& operator=(const InternalRgbKeyboard&) = delete;
  ~InternalRgbKeyboard() override = default;

  bool SetKeyColor(uint32_t key, uint8_t r, uint8_t g, uint8_t b) override;
  bool SetAllKeyColors(uint8_t r, uint8_t g, uint8_t b) override;
  RgbKeyboardCapabilities GetRgbKeyboardCapabilities() override;

  void ResetUsbKeyboard() override;
  void InitializeUsbKeyboard() override;

 private:
  enum class CommunicationType {
    kUsb = 0,
    kFileDescriptor = 1,
  };

  // When calling EC commands, we have to figure out whether the rgb
  // keyboard communicates over USB or File Descriptor. This takes an EcCommand
  // and tries it both over USB and FD. If either succeeds it saves which type
  // to use in future EcCommands.
  template <typename T, typename S>
  bool SetCommunicationType(ec::EcCommand<T, S>& command);
  template <typename T, typename S>
  bool RunEcCommand(ec::EcCommand<T, S>& command);

  std::optional<CommunicationType> communication_type_;
  std::unique_ptr<ec::EcUsbEndpointInterface> usb_endpoint_;
  base::ScopedFD ec_fd_;
};

}  // namespace rgbkbd

#endif  // RGBKBD_INTERNAL_RGB_KEYBOARD_H_
