// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_FUTILITY_UTILS_H_
#define RMAD_UTILS_FUTILITY_UTILS_H_

namespace rmad {

class FutilityUtils {
 public:
  FutilityUtils() = default;
  virtual ~FutilityUtils() = default;

  virtual bool GetApWriteProtectionStatus(bool* enabled) = 0;
  virtual bool EnableApSoftwareWriteProtection() = 0;
  virtual bool DisableApSoftwareWriteProtection() = 0;
};

}  // namespace rmad

#endif  // RMAD_UTILS_FUTILITY_UTILS_H_
