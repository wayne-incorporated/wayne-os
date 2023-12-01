// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_SYS_UTILS_IMPL_H_
#define RMAD_UTILS_SYS_UTILS_IMPL_H_

#include <rmad/utils/sys_utils.h>

#include <base/files/file_path.h>

namespace rmad {

class SysUtilsImpl : public SysUtils {
 public:
  SysUtilsImpl();
  explicit SysUtilsImpl(const base::FilePath& sys_path);
  ~SysUtilsImpl() override = default;

  bool IsPowerSourcePresent() const override;

 private:
  base::FilePath sys_path_;
};

}  // namespace rmad

#endif  // RMAD_UTILS_SYS_UTILS_IMPL_H_
