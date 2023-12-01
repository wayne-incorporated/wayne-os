// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_PD_CHIP_INFO_COMMAND_H_
#define LIBEC_PD_CHIP_INFO_COMMAND_H_

#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT PdChipInfoCommandV0
    : public EcCommand<struct ec_params_pd_chip_info,
                       struct ec_response_pd_chip_info> {
 public:
  explicit PdChipInfoCommandV0(uint8_t port, uint8_t live)
      : EcCommand(EC_CMD_PD_CHIP_INFO, 0, {.port = port, .live = live}) {}
  ~PdChipInfoCommandV0() override = default;

  uint16_t VendorId() const { return Resp()->vendor_id; }
  uint16_t ProductId() const { return Resp()->product_id; }
  uint16_t DeviceId() const { return Resp()->device_id; }
};

static_assert(!std::is_copy_constructible<PdChipInfoCommandV0>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<PdChipInfoCommandV0>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_PD_CHIP_INFO_COMMAND_H_
