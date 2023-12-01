// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_SET_MKBP_WAKE_MASK_COMMAND_H_
#define LIBEC_SET_MKBP_WAKE_MASK_COMMAND_H_

#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT SetMkbpWakeMaskCommand
    : public EcCommand<struct ec_params_mkbp_event_wake_mask, EmptyParam> {
 public:
  SetMkbpWakeMaskCommand(enum ec_mkbp_mask_type mask_type,
                         uint32_t new_wake_mask);
  ~SetMkbpWakeMaskCommand() override = default;
};

class BRILLO_EXPORT SetMkbpWakeMaskHostEventCommand
    : public SetMkbpWakeMaskCommand {
 public:
  explicit SetMkbpWakeMaskHostEventCommand(uint32_t new_wake_mask);
  ~SetMkbpWakeMaskHostEventCommand() override = default;
};

class BRILLO_EXPORT SetMkbpWakeMaskEventCommand
    : public SetMkbpWakeMaskCommand {
 public:
  explicit SetMkbpWakeMaskEventCommand(uint32_t new_wake_mask);
  ~SetMkbpWakeMaskEventCommand() override = default;
};

static_assert(!std::is_copy_constructible<SetMkbpWakeMaskCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<SetMkbpWakeMaskCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_SET_MKBP_WAKE_MASK_COMMAND_H_
