// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DISCOD_CONTROL_LOOP_H_
#define DISCOD_CONTROL_LOOP_H_

#include <memory>

#include <base/threading/thread.h>
#include <brillo/blkdev_utils/disk_iostat.h>

#include "discod/controls/ufs_write_booster_control_logic.h"
#include "discod/metrics/metrics.h"

namespace discod {

class ControlLoop : public base::Thread {
 public:
  ControlLoop(std::unique_ptr<UfsWriteBoosterControlLogic>
                  ufs_write_boost_control_logic,
              std::unique_ptr<brillo::DiskIoStat> disk_io_stat,
              std::unique_ptr<Metrics> metrics);
  ControlLoop(const ControlLoop&) = delete;
  ControlLoop& operator=(const ControlLoop&) = delete;
  ~ControlLoop() override = default;

  void StartControlLogic();
  void EnableWriteBoost();

 private:
  std::unique_ptr<UfsWriteBoosterControlLogic> ufs_write_boost_control_logic_;
  std::unique_ptr<brillo::DiskIoStat> disk_io_stat_;
  std::unique_ptr<Metrics> metrics_;
  brillo::DiskIoStat::Snapshot latest_snapshot_;

  void HandleControlLogic();
  void HandleEnableWriteBooster();
  void ScheduleControlLogicTick();
};

}  // namespace discod

#endif  // DISCOD_CONTROL_LOOP_H_
