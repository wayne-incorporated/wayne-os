// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_FINGERPRINT_FP_STATS_COMMAND_H_
#define LIBEC_FINGERPRINT_FP_STATS_COMMAND_H_

#include <optional>

#include <base/time/time.h>
#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT FpStatsCommand
    : public EcCommand<EmptyParam, struct ec_response_fp_stats> {
 public:
  FpStatsCommand() : EcCommand(EC_CMD_FP_STATS) {}
  ~FpStatsCommand() override = default;

  std::optional<base::TimeDelta> CaptureTime() const;
  std::optional<base::TimeDelta> MatchingTime() const;
  base::TimeDelta OverallTime() const;
};

static_assert(!std::is_copy_constructible<FpStatsCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<FpStatsCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_FINGERPRINT_FP_STATS_COMMAND_H_
