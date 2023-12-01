// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DISCOD_CONTROLS_UFS_WRITE_BOOSTER_CONTROL_LOGIC_H_
#define DISCOD_CONTROLS_UFS_WRITE_BOOSTER_CONTROL_LOGIC_H_

#include <base/time/time.h>
#include <brillo/blkdev_utils/disk_iostat.h>

#include "discod/utils/libhwsec_status_import.h"

namespace discod {

class UfsWriteBoosterControlLogic {
 public:
  UfsWriteBoosterControlLogic() = default;
  UfsWriteBoosterControlLogic(const UfsWriteBoosterControlLogic&) = delete;
  UfsWriteBoosterControlLogic& operator=(const UfsWriteBoosterControlLogic&) =
      delete;
  virtual ~UfsWriteBoosterControlLogic() = default;

  virtual Status Reset() = 0;
  virtual Status Update(const brillo::DiskIoStat::Delta& delta) = 0;
  virtual Status Enable() = 0;
};

}  // namespace discod

#endif  // DISCOD_CONTROLS_UFS_WRITE_BOOSTER_CONTROL_LOGIC_H_
