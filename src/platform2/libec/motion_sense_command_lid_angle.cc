// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/motion_sense_command_lid_angle.h"

namespace ec {

MotionSenseCommandLidAngle::MotionSenseCommandLidAngle()
    : MotionSenseCommand(2) {
  SetReq({.cmd = MOTIONSENSE_CMD_LID_ANGLE});
  SetReqSize(sizeof(ec_params_motion_sense::cmd));
  SetRespSize(sizeof(ec_response_motion_sense::lid_angle));
}

uint16_t MotionSenseCommandLidAngle::LidAngle() const {
  return Resp()->lid_angle.value;
}

}  // namespace ec
