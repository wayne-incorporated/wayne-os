// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/grpc/time_util.h"

#include <grpc/support/time.h>

namespace brillo {

gpr_timespec GprTimespecWithDeltaFromNow(base::TimeDelta delta) {
  return gpr_time_add(
      gpr_now(GPR_CLOCK_MONOTONIC),
      gpr_time_from_millis(delta.InMilliseconds(), GPR_TIMESPAN));
}

}  // namespace brillo
