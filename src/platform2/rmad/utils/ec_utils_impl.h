// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_EC_UTILS_IMPL_H_
#define RMAD_UTILS_EC_UTILS_IMPL_H_

#include "rmad/utils/ec_utils.h"

#include <base/files/scoped_file.h>

// TODO(b/144956297): Add unittest after RebootCommand can be mocked.

namespace rmad {

class EcUtilsImpl : public EcUtils {
 public:
  EcUtilsImpl() = default;
  ~EcUtilsImpl() override = default;

  bool Reboot() override;
  bool GetEcWriteProtectionStatus(bool* enabled) override;
  bool EnableEcSoftwareWriteProtection() override;
  bool DisableEcSoftwareWriteProtection() override;

 private:
  bool SetEcSoftwareWriteProtection(bool enable);
  base::ScopedFD GetEcFd() const;
};

}  // namespace rmad

#endif  // RMAD_UTILS_EC_UTILS_IMPL_H_
