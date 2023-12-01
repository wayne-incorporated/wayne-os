// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_RGB_KEYBOARD_PARAMS_H_
#define LIBEC_RGB_KEYBOARD_PARAMS_H_

#include <array>

#include "libec/ec_command.h"

namespace ec {
namespace rgb_keyboard {

// We cannot use "struct ec_params_rgbkbd_set_color" directly in the
// RgbkbdSetColorCommand class because the "color" member is a variable length
// array. "Header" includes everything from that struct except "color".
struct Header {
  uint8_t start_key = 0;
  uint8_t length = 0;
};

using Color = std::array<struct rgb_s, EC_RGBKBD_MAX_KEY_COUNT>;

struct Params {
  struct Header req;
  Color color{};
};

}  // namespace rgb_keyboard
}  // namespace ec

#endif  // LIBEC_RGB_KEYBOARD_PARAMS_H_
