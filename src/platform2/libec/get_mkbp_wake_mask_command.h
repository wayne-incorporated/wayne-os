// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_GET_MKBP_WAKE_MASK_COMMAND_H_
#define LIBEC_GET_MKBP_WAKE_MASK_COMMAND_H_

#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT GetMkbpWakeMaskCommand
    : public EcCommand<struct ec_params_mkbp_event_wake_mask,
                       struct ec_response_mkbp_event_wake_mask> {
 public:
  explicit GetMkbpWakeMaskCommand(enum ec_mkbp_mask_type mask_type);
  ~GetMkbpWakeMaskCommand() override = default;

  uint32_t GetWakeMask() const;
};

class BRILLO_EXPORT GetMkbpWakeMaskHostEventCommand
    : public GetMkbpWakeMaskCommand {
 public:
  GetMkbpWakeMaskHostEventCommand();
  ~GetMkbpWakeMaskHostEventCommand() override = default;

  bool IsEnabled(enum host_event_code event) const;
};

class BRILLO_EXPORT GetMkbpWakeMaskEventCommand
    : public GetMkbpWakeMaskCommand {
 public:
  GetMkbpWakeMaskEventCommand();
  ~GetMkbpWakeMaskEventCommand() override = default;

  bool IsEnabled(enum ec_mkbp_event event) const;
};

static_assert(!std::is_copy_constructible<GetMkbpWakeMaskCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<GetMkbpWakeMaskCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_GET_MKBP_WAKE_MASK_COMMAND_H_
