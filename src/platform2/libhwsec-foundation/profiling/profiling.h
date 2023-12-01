// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_PROFILING_PROFILING_H_
#define LIBHWSEC_FOUNDATION_PROFILING_PROFILING_H_

#include "libhwsec-foundation/hwsec-foundation_export.h"

namespace hwsec_foundation {

// Sets up filename and starts code profiling. This method
// needs to be called from the main function in order to
// start profiling.
HWSEC_FOUNDATION_EXPORT void SetUpProfiling();

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_PROFILING_PROFILING_H_
