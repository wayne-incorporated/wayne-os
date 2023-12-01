// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "discod/control_loop.h"

#include <memory>
#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/threading/thread.h>
#include <base/time/time.h>
#include <brillo/blkdev_utils/disk_iostat.h>

#include "discod/controls/ufs_write_booster_control_logic.h"
#include "discod/metrics/metrics.h"

namespace discod {

namespace {

void LogControlLoopStatus(Status status) {
  if (!status.ok()) {
    LOG(ERROR) << status;
  }
}

}  // namespace

ControlLoop::ControlLoop(
    std::unique_ptr<UfsWriteBoosterControlLogic> ufs_write_boost_control_logic,
    std::unique_ptr<brillo::DiskIoStat> disk_io_stat,
    std::unique_ptr<Metrics> metrics)
    : base::Thread("discod_control_loop"),
      ufs_write_boost_control_logic_(std::move(ufs_write_boost_control_logic)),
      disk_io_stat_(std::move(disk_io_stat)),
      metrics_(std::move(metrics)) {}

void ControlLoop::StartControlLogic() {
  VLOG(3) << __func__;
  WaitUntilThreadStarted();
  LogControlLoopStatus(ufs_write_boost_control_logic_->Reset());
  ScheduleControlLogicTick();
}

void ControlLoop::EnableWriteBoost() {
  VLOG(3) << __func__;
  if (!IsRunning()) {
    VLOG(3) << "Control Loop is not running";
    return;
  }
  task_runner()->PostTask(FROM_HERE,
                          base::BindOnce(&ControlLoop::HandleEnableWriteBooster,
                                         base::Unretained(this)));
}

void ControlLoop::HandleControlLogic() {
  VLOG(3) << __func__;
  std::optional<brillo::DiskIoStat::Snapshot> snapshot =
      disk_io_stat_->GetSnapshot();

  if (snapshot.has_value()) {
    if (latest_snapshot_.IsValid()) {
      LogControlLoopStatus(ufs_write_boost_control_logic_->Update(
          snapshot->Delta(latest_snapshot_)));
    }
    latest_snapshot_ = snapshot.value();
  }

  ScheduleControlLogicTick();
}

void ControlLoop::HandleEnableWriteBooster() {
  VLOG(3) << __func__;
  LogControlLoopStatus(ufs_write_boost_control_logic_->Enable());
}

void ControlLoop::ScheduleControlLogicTick() {
  VLOG(3) << __func__;
  if (!IsRunning()) {
    VLOG(3) << "Control Loop is not running";
    return;
  }
  task_runner()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ControlLoop::HandleControlLogic, base::Unretained(this)),
      base::Seconds(1));
}

}  // namespace discod
