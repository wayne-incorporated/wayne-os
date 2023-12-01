// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DISCOD_CONTROLS_MOCK_UFS_WRITE_BOOSTER_CONTROL_LOGIC_H_
#define DISCOD_CONTROLS_MOCK_UFS_WRITE_BOOSTER_CONTROL_LOGIC_H_

#include <base/time/time.h>
#include <brillo/blkdev_utils/disk_iostat.h>
#include <gmock/gmock.h>

#include "discod/controls/ufs_write_booster_control_logic.h"
#include "discod/utils/libhwsec_status_import.h"

namespace discod {

class MockUfsWriteBoosterControlLogic : public UfsWriteBoosterControlLogic {
 public:
  MockUfsWriteBoosterControlLogic() = default;
  MockUfsWriteBoosterControlLogic(const MockUfsWriteBoosterControlLogic&) =
      delete;
  MockUfsWriteBoosterControlLogic& operator=(
      const MockUfsWriteBoosterControlLogic&) = delete;
  ~MockUfsWriteBoosterControlLogic() override = default;

  MOCK_METHOD(Status, Reset, (), (override));
  MOCK_METHOD(Status,
              Update,
              (const brillo::DiskIoStat::Delta& delta),
              (override));
  MOCK_METHOD(Status, Enable, (), (override));
};

}  // namespace discod

#endif  // DISCOD_CONTROLS_MOCK_UFS_WRITE_BOOSTER_CONTROL_LOGIC_H_
