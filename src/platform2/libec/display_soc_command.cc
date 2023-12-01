// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/display_soc_command.h"

namespace ec {

double DisplayStateOfChargeCommand::CurrentPercentCharge() const {
  return Resp()->display_soc / 10.0;
}

double DisplayStateOfChargeCommand::FullFactor() const {
  return Resp()->full_factor / 1000.0;
}

double DisplayStateOfChargeCommand::ShutdownPercentCharge() const {
  return Resp()->shutdown_soc / 10.0;
}

}  // namespace ec
