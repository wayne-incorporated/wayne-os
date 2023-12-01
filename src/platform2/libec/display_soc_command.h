// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_DISPLAY_SOC_COMMAND_H_
#define LIBEC_DISPLAY_SOC_COMMAND_H_

#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT DisplayStateOfChargeCommand
    : public EcCommand<EmptyParam, struct ec_response_display_soc> {
 public:
  DisplayStateOfChargeCommand() : EcCommand(EC_CMD_DISPLAY_SOC) {}
  ~DisplayStateOfChargeCommand() override = default;

  double CurrentPercentCharge() const;
  double FullFactor() const;
  double ShutdownPercentCharge() const;
};

static_assert(!std::is_copy_constructible<DisplayStateOfChargeCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<DisplayStateOfChargeCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_DISPLAY_SOC_COMMAND_H_
