// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_SMART_DISCHARGE_COMMAND_H_
#define LIBEC_SMART_DISCHARGE_COMMAND_H_

#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT SmartDischargeCommand
    : public EcCommand<struct ec_params_smart_discharge,
                       struct ec_response_smart_discharge> {
 public:
  SmartDischargeCommand() : EcCommand(EC_CMD_SMART_DISCHARGE) {}
  SmartDischargeCommand(uint16_t hours_to_zero,
                        uint16_t cutoff_current_ua,
                        uint16_t hibernation_current_ua)
      : EcCommand(EC_CMD_SMART_DISCHARGE) {
    Req()->flags = EC_SMART_DISCHARGE_FLAGS_SET;
    Req()->hours_to_zero = hours_to_zero;
    Req()->drate.cutoff = cutoff_current_ua;
    Req()->drate.hibern = hibernation_current_ua;
  }
  ~SmartDischargeCommand() override = default;

  uint16_t HoursToZero() const;
  uint16_t CutoffCurrentMicroAmps() const;
  uint16_t HibernationCurrentMicroAmps() const;
  int BatteryCutoffThresholdMilliAmpHours() const;
  int ECStayupThresholdMilliAmpHours() const;
};

static_assert(!std::is_copy_constructible<SmartDischargeCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<SmartDischargeCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_SMART_DISCHARGE_COMMAND_H_
