// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_GRPC_TIME_UTIL_H_
#define LIBBRILLO_BRILLO_GRPC_TIME_UTIL_H_

#include <base/time/time.h>
#include <brillo/brillo_export.h>
#include <grpcpp/support/time.h>

namespace brillo {

BRILLO_EXPORT gpr_timespec GprTimespecWithDeltaFromNow(base::TimeDelta delta);

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_GRPC_TIME_UTIL_H_
