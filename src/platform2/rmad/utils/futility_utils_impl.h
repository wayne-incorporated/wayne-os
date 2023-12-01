// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_FUTILITY_UTILS_IMPL_H_
#define RMAD_UTILS_FUTILITY_UTILS_IMPL_H_

#include <rmad/utils/futility_utils.h>

#include <memory>

#include "rmad/utils/cmd_utils.h"

namespace rmad {

class FutilityUtilsImpl : public FutilityUtils {
 public:
  FutilityUtilsImpl();
  explicit FutilityUtilsImpl(std::unique_ptr<CmdUtils> cmd_utils);
  ~FutilityUtilsImpl() override = default;

  bool GetApWriteProtectionStatus(bool* enabled) override;
  bool EnableApSoftwareWriteProtection() override;
  bool DisableApSoftwareWriteProtection() override;

 private:
  std::unique_ptr<CmdUtils> cmd_utils_;
};

}  // namespace rmad

#endif  // RMAD_UTILS_FUTILITY_UTILS_IMPL_H_
