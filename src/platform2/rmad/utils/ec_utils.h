// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_EC_UTILS_H_
#define RMAD_UTILS_EC_UTILS_H_

#include <string>

namespace rmad {

class EcUtils {
 public:
  EcUtils() = default;
  virtual ~EcUtils() = default;

  virtual bool Reboot() = 0;
  virtual bool GetEcWriteProtectionStatus(bool* enabled) = 0;
  virtual bool EnableEcSoftwareWriteProtection() = 0;
  virtual bool DisableEcSoftwareWriteProtection() = 0;

  // TODO(b/242143606): Merge CbiUtils to this class.
};

}  // namespace rmad

#endif  // RMAD_UTILS_EC_UTILS_H_
