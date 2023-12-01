// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_SYSTEM_UTILITIES_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_SYSTEM_UTILITIES_H_

#include <sys/utsname.h>

namespace diagnostics {

// Interface which wraps system utilities which are hard to unit test.
class SystemUtilities {
 public:
  virtual ~SystemUtilities() = default;

  // Runs the uname utility.
  virtual int Uname(struct utsname* buf) = 0;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_SYSTEM_UTILITIES_H_
