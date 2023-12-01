// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_WRITE_PROTECT_UTILS_H_
#define RMAD_UTILS_WRITE_PROTECT_UTILS_H_

namespace rmad {

class WriteProtectUtils {
 public:
  WriteProtectUtils() = default;
  virtual ~WriteProtectUtils() = default;

  virtual bool GetHardwareWriteProtectionStatus(bool* enabled) const = 0;
  virtual bool GetApWriteProtectionStatus(bool* enabled) const = 0;
  virtual bool GetEcWriteProtectionStatus(bool* enabled) const = 0;
  // Disable both AP and EC write protection.
  virtual bool DisableSoftwareWriteProtection() = 0;
  // Enable both AP and EC write protection.
  virtual bool EnableSoftwareWriteProtection() = 0;
};

}  // namespace rmad

#endif  // RMAD_UTILS_WRITE_PROTECT_UTILS_H_
