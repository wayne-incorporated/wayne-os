// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/cicerone/grpc_util.h"

#include <grpcpp/grpcpp.h>

namespace vm_tools {
namespace cicerone {

gpr_timespec ToGprDeadline(int64_t seconds) {
  return gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC),
                      gpr_time_from_seconds(seconds, GPR_TIMESPAN));
}

}  // namespace cicerone
}  // namespace vm_tools
