// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DISCOD_CONTROLS_REAL_UFS_WRITE_BOOSTER_CONTROL_LOGIC_H_
#define DISCOD_CONTROLS_REAL_UFS_WRITE_BOOSTER_CONTROL_LOGIC_H_

#include <memory>

#include <base/time/time.h>
#include <brillo/blkdev_utils/disk_iostat.h>

#include "discod/controls/binary_control.h"
#include "discod/controls/ufs_write_booster_control_logic.h"
#include "discod/metrics/metrics.h"
#include "discod/utils/libhwsec_status_import.h"

namespace discod {

class RealUfsWriteBoosterControlLogic : public UfsWriteBoosterControlLogic {
 public:
  RealUfsWriteBoosterControlLogic(std::unique_ptr<BinaryControl> control,
                                  Metrics* metrics);
  RealUfsWriteBoosterControlLogic(const RealUfsWriteBoosterControlLogic&) =
      delete;
  RealUfsWriteBoosterControlLogic& operator=(
      const RealUfsWriteBoosterControlLogic&) = delete;
  ~RealUfsWriteBoosterControlLogic() override = default;

  Status Reset() override;
  Status Update(const brillo::DiskIoStat::Delta& delta) override;
  Status Enable() override;

 private:
  std::unique_ptr<BinaryControl> control_;
  Metrics* metrics_;  // not-owned;

  uint64_t cycles_over_write_threshold_ = 0;
  uint64_t cycles_under_write_threshold_ = 0;
  bool explicit_trigger_ = false;
  BinaryControl::State last_decision_ = BinaryControl::State::kOff;

  uint64_t wb_on_cycles_ = 0;
  uint64_t wb_on_with_high_traffic_cycles_ = 0;

  void UpdateStatistics(uint64_t bw);
  BinaryControl::State CalculateTargetState();
  Status UpdateState(BinaryControl::State target);
  void SendWBActivityUMA();

  // Used for UMA, don't change existing values, do not re-use old values, sync
  // updates with tools/metrics/histograms/enums.xml
  enum BurstResult {
    kRemain = 0,
    kEnable = 1,
    kMaxValue,
  };

  void SendBurstResultUMA(BurstResult value);
};

}  // namespace discod

#endif  // DISCOD_CONTROLS_REAL_UFS_WRITE_BOOSTER_CONTROL_LOGIC_H_
