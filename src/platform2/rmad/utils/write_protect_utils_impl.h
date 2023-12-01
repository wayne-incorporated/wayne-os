// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_WRITE_PROTECT_UTILS_IMPL_H_
#define RMAD_UTILS_WRITE_PROTECT_UTILS_IMPL_H_

#include "rmad/utils/write_protect_utils.h"

#include <memory>

#include "rmad/utils/crossystem_utils.h"
#include "rmad/utils/ec_utils.h"
#include "rmad/utils/futility_utils.h"

namespace rmad {

class WriteProtectUtilsImpl : public WriteProtectUtils {
 public:
  WriteProtectUtilsImpl();
  explicit WriteProtectUtilsImpl(
      std::unique_ptr<CrosSystemUtils> crossystem_utils,
      std::unique_ptr<EcUtils> ec_utils,
      std::unique_ptr<FutilityUtils> futility_utils);
  ~WriteProtectUtilsImpl() override = default;

  bool GetHardwareWriteProtectionStatus(bool* enabled) const override;
  bool GetApWriteProtectionStatus(bool* enabled) const override;
  bool GetEcWriteProtectionStatus(bool* enabled) const override;
  bool DisableSoftwareWriteProtection() override;
  bool EnableSoftwareWriteProtection() override;

 private:
  std::unique_ptr<CrosSystemUtils> crossystem_utils_;
  std::unique_ptr<EcUtils> ec_utils_;
  std::unique_ptr<FutilityUtils> futility_utils_;
};

}  // namespace rmad

#endif  // RMAD_UTILS_WRITE_PROTECT_UTILS_IMPL_H_
