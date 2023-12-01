// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_RGB_KEYBOARD_COMMAND_H_
#define LIBEC_RGB_KEYBOARD_COMMAND_H_

#include <algorithm>
#include <memory>
#include <vector>

#include <base/memory/ptr_util.h>
#include <brillo/brillo_export.h>
#include "libec/ec_command.h"
#include "libec/rgb_keyboard_params.h"

namespace ec {

class BRILLO_EXPORT RgbkbdSetColorCommand
    : public EcCommand<rgb_keyboard::Params, EmptyParam> {
 public:
  // <start_key> is the first ID of the keys whose colors will be changed to the
  // colors specified by <color>.
  explicit RgbkbdSetColorCommand(uint8_t start_key = 0,
                                 const std::vector<struct rgb_s>& color = {})
      : EcCommand(EC_CMD_RGBKBD_SET_COLOR, 0) {
    Req()->req.start_key = start_key;
    Req()->req.length = color.size();
    std::copy(color.begin(), color.end(), Req()->color.begin());
    SetReqSize(sizeof(rgb_keyboard::Header) +
               Req()->req.length * sizeof(Req()->color[0]));
  }
  ~RgbkbdSetColorCommand() override = default;
};

static_assert(!std::is_copy_constructible<RgbkbdSetColorCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<RgbkbdSetColorCommand>::value,
              "EcCommands are not copy-assignable by default");

class BRILLO_EXPORT RgbkbdCommand
    : public EcCommand<struct ec_params_rgbkbd, struct ec_response_rgbkbd> {
 public:
  RgbkbdCommand() : EcCommand(EC_CMD_RGBKBD, 0) {}
  template <typename T = RgbkbdCommand>
  static std::unique_ptr<T> Create(enum ec_rgbkbd_subcmd subcmd,
                                   struct rgb_s color) {
    static_assert(std::is_base_of<RgbkbdCommand, T>::value,
                  "Only classes derived from RgbkbdCommand can use Create");

    if (subcmd < 0 || subcmd >= EC_RGBKBD_SUBCMD_COUNT) {
      return nullptr;
    }

    return base::WrapUnique(new T(subcmd, color));
  }

  template <typename T = RgbkbdCommand>
  static std::unique_ptr<T> Create(enum ec_rgbkbd_subcmd subcmd) {
    static_assert(std::is_base_of<RgbkbdCommand, T>::value,
                  "Only classes derived from RgbkbdCommand can use Create");

    if (subcmd != EC_RGBKBD_SUBCMD_GET_CONFIG) {
      return nullptr;
    }

    return base::WrapUnique(new T(subcmd));
  }

  ~RgbkbdCommand() override = default;

  uint8_t GetConfig() const { return Resp()->rgbkbd_type; }

 protected:
  RgbkbdCommand(enum ec_rgbkbd_subcmd subcmd, struct rgb_s color)
      : EcCommand(EC_CMD_RGBKBD, 0) {
    Req()->subcmd = subcmd;
    Req()->color = color;
  }

  explicit RgbkbdCommand(enum ec_rgbkbd_subcmd subcmd)
      : EcCommand(EC_CMD_RGBKBD, 0) {
    Req()->subcmd = subcmd;
  }
};

static_assert(!std::is_copy_constructible<RgbkbdCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<RgbkbdCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_RGB_KEYBOARD_COMMAND_H_
