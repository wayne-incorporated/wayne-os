// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_FINGERPRINT_FP_MODE_COMMAND_H_
#define LIBEC_FINGERPRINT_FP_MODE_COMMAND_H_

#include <base/check_op.h>
#include <brillo/brillo_export.h>
#include "libec/ec_command.h"
#include "libec/fingerprint/fp_mode.h"

namespace ec {

class BRILLO_EXPORT FpModeCommand
    : public EcCommand<struct ec_params_fp_mode, struct ec_response_fp_mode> {
 public:
  explicit FpModeCommand(FpMode mode) : EcCommand(EC_CMD_FP_MODE) {
    CHECK(mode != FpMode(FpMode::Mode::kModeInvalid));
    Req()->mode = mode.RawVal();
  }
  ~FpModeCommand() override = default;

  FpMode Mode() const;
};

/**
 * Get the current FpMode.
 */
class BRILLO_EXPORT GetFpModeCommand : public FpModeCommand {
 public:
  GetFpModeCommand() : FpModeCommand(FpMode(FpMode::Mode::kDontChange)) {}
  ~GetFpModeCommand() override = default;
};

static_assert(!std::is_copy_constructible<FpModeCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<FpModeCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_FINGERPRINT_FP_MODE_COMMAND_H_
