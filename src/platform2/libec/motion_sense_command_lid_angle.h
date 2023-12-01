// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_MOTION_SENSE_COMMAND_LID_ANGLE_H_
#define LIBEC_MOTION_SENSE_COMMAND_LID_ANGLE_H_

#include <brillo/brillo_export.h>

#include "libec/motion_sense_command.h"

namespace ec {

class BRILLO_EXPORT MotionSenseCommandLidAngle : public MotionSenseCommand {
 public:
  MotionSenseCommandLidAngle();
  ~MotionSenseCommandLidAngle() override = default;

  uint16_t LidAngle() const;
};

static_assert(!std::is_copy_constructible<MotionSenseCommandLidAngle>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<MotionSenseCommandLidAngle>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_MOTION_SENSE_COMMAND_LID_ANGLE_H_
