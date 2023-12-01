// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_MOTION_SENSE_COMMAND_H_
#define LIBEC_MOTION_SENSE_COMMAND_H_

#include <brillo/brillo_export.h>

#include "libec/ec_command.h"

namespace ec {

class MotionSenseCommand : public EcCommand<struct ec_params_motion_sense,
                                            struct ec_response_motion_sense> {
 public:
  explicit MotionSenseCommand(uint32_t ver = 0)
      : EcCommand(EC_CMD_MOTION_SENSE_CMD, ver) {}
  ~MotionSenseCommand() override = default;
};

static_assert(!std::is_copy_constructible<MotionSenseCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<MotionSenseCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_MOTION_SENSE_COMMAND_H_
