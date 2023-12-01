// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_SYS_UTILS_H_
#define RMAD_UTILS_SYS_UTILS_H_

#include <string>

namespace rmad {

class SysUtils {
 public:
  SysUtils() = default;
  virtual ~SysUtils() = default;

  // Check if power source is present.
  virtual bool IsPowerSourcePresent() const = 0;
};

}  // namespace rmad

#endif  // RMAD_UTILS_SYS_UTILS_H_
