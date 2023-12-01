// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/smart_discharge_command.h"

namespace ec {

uint16_t SmartDischargeCommand::HoursToZero() const {
  return Resp()->hours_to_zero;
}

uint16_t SmartDischargeCommand::CutoffCurrentMicroAmps() const {
  return Resp()->drate.cutoff;
}

uint16_t SmartDischargeCommand::HibernationCurrentMicroAmps() const {
  return Resp()->drate.hibern;
}

int SmartDischargeCommand::BatteryCutoffThresholdMilliAmpHours() const {
  return Resp()->dzone.cutoff;
}

int SmartDischargeCommand::ECStayupThresholdMilliAmpHours() const {
  return Resp()->dzone.stayup;
}

}  // namespace ec
