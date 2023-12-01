// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "discod/controls/real_ufs_write_booster_control_logic.h"

#include <base/time/time.h>
#include <brillo/blkdev_utils/disk_iostat.h>
#include <gtest/gtest.h>

#include "discod/controls/fake_binary_control.h"
#include "discod/metrics/mock_metrics.h"
#include "discod/utils/libhwsec_status_import.h"

namespace discod {
namespace {

constexpr int kBurstMaxVal = 2;
constexpr int kCyclesMinVal = 0;
constexpr int kCyclesMaxVal = 10000;
constexpr int kCyclesBuckets = 100;

using testing::_;
using testing::StrictMock;

class RealUfsWriteBoosterControlLogicTest : public ::testing::Test {
 public:
  RealUfsWriteBoosterControlLogicTest()
      : binary_control_(new FakeBinaryControl()),
        control_logic_(std::unique_ptr<BinaryControl>(binary_control_),
                       &metrics_) {
    brillo::DiskIoStat::Stat over_stat = {.write_sectors = 75 * 256};
    brillo::DiskIoStat::Stat under_stat = {.write_sectors = 25 * 256};
    over_threshold_delta_ = brillo::DiskIoStat::Delta(
        brillo::DiskIoStat::Snapshot(base::Seconds(1), over_stat));
    under_threshold_delta_ = brillo::DiskIoStat::Delta(
        brillo::DiskIoStat::Snapshot(base::Seconds(1), under_stat));

    EXPECT_CALL(metrics_, SendToUMA(_, _, _, _, _)).Times(0);
    EXPECT_CALL(metrics_, SendPercentageToUMA(_, _)).Times(0);
    EXPECT_CALL(metrics_, SendEnumToUMA(_, _, _)).Times(0);
  }

  ~RealUfsWriteBoosterControlLogicTest() override = default;

 protected:
  StrictMock<MockMetrics> metrics_;
  FakeBinaryControl* binary_control_;  // owned by control_logic_
  RealUfsWriteBoosterControlLogic control_logic_;

  brillo::DiskIoStat::Delta over_threshold_delta_;
  brillo::DiskIoStat::Delta under_threshold_delta_;
};

}  // namespace

TEST_F(RealUfsWriteBoosterControlLogicTest, ErrorPropagation) {
  // Default false after first Update.
  ASSERT_THAT(control_logic_.Reset(), IsOk());
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOff);

  for (int i = 0; i < 2; ++i) {
    EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOff);
    ASSERT_THAT(control_logic_.Update(over_threshold_delta_), IsOk());
  }
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOff);

  // Inject error
  binary_control_->InjectError("XXX");
  // Expect error instead of state transition.
  EXPECT_CALL(metrics_, SendEnumToUMA(kBurstResultHistogram, 1, kBurstMaxVal))
      .Times(1);
  ASSERT_THAT(control_logic_.Update(over_threshold_delta_), NotOk());

  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOff);

  // Next update succeeds.
  EXPECT_CALL(metrics_, SendEnumToUMA(kBurstResultHistogram, 1, kBurstMaxVal))
      .Times(1);
  ASSERT_THAT(control_logic_.Update(over_threshold_delta_), IsOk());
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOn);

  // Trigger turn off.
  EXPECT_CALL(metrics_, SendPercentageToUMA(kAutoWbBwUtilizationHistogram, 80))
      .Times(1);
  EXPECT_CALL(metrics_, SendToUMA(kAutoWbOnCyclesHistogram, 5, kCyclesMinVal,
                                  kCyclesMaxVal, kCyclesBuckets))
      .Times(1);
  for (int i = 0; i < 5; ++i) {
    EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOn);
    ASSERT_THAT(control_logic_.Update(under_threshold_delta_), IsOk());
  }
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOff);

  // Inject error
  binary_control_->InjectError("XXX");

  // Expect and error on enable
  EXPECT_THAT(control_logic_.Enable(), NotOk());
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOff);

  // Next one succeeds
  EXPECT_THAT(control_logic_.Enable(), IsOk());
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOn);
}

TEST_F(RealUfsWriteBoosterControlLogicTest, NoExplicitTrigger) {
  ASSERT_THAT(control_logic_.Reset(), IsOk());
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOff);

  // Off when under threshold
  for (int i = 0; i < 10; ++i) {
    ASSERT_THAT(control_logic_.Update(under_threshold_delta_), IsOk());
    EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOff);
  }

  // Off->On counter reset when under threshold
  ASSERT_THAT(control_logic_.Update(over_threshold_delta_), IsOk());
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOff);

  EXPECT_CALL(metrics_, SendEnumToUMA(kBurstResultHistogram, 0, kBurstMaxVal))
      .Times(1);
  ASSERT_THAT(control_logic_.Update(under_threshold_delta_), IsOk());
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOff);

  for (int i = 0; i < 2; ++i) {
    EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOff);
    ASSERT_THAT(control_logic_.Update(over_threshold_delta_), IsOk());
  }
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOff);

  EXPECT_CALL(metrics_, SendEnumToUMA(kBurstResultHistogram, 0, kBurstMaxVal))
      .Times(1);
  ASSERT_THAT(control_logic_.Update(under_threshold_delta_), IsOk());
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOff);

  // Off->On when overthreshold for hysteresis period
  EXPECT_CALL(metrics_, SendEnumToUMA(kBurstResultHistogram, 1, kBurstMaxVal))
      .Times(1);
  for (int i = 0; i < 3; ++i) {
    EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOff);
    ASSERT_THAT(control_logic_.Update(over_threshold_delta_), IsOk());
  }
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOn);

  // On->Off counter reset when over threshold
  for (int i = 0; i < 3; ++i) {
    EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOn);
    ASSERT_THAT(control_logic_.Update(under_threshold_delta_), IsOk());
  }
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOn);

  ASSERT_THAT(control_logic_.Update(over_threshold_delta_), IsOk());

  for (int i = 0; i < 3; ++i) {
    EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOn);
    ASSERT_THAT(control_logic_.Update(under_threshold_delta_), IsOk());
  }
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOn);

  ASSERT_THAT(control_logic_.Update(over_threshold_delta_), IsOk());

  // On->Off when under threshold for hysteresis
  EXPECT_CALL(metrics_, SendPercentageToUMA(kAutoWbBwUtilizationHistogram, 61))
      .Times(1);
  EXPECT_CALL(metrics_, SendToUMA(kAutoWbOnCyclesHistogram, 13, kCyclesMinVal,
                                  kCyclesMaxVal, kCyclesBuckets))
      .Times(1);
  for (int i = 0; i < 5; ++i) {
    EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOn);
    ASSERT_THAT(control_logic_.Update(under_threshold_delta_), IsOk());
  }
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOff);
}

TEST_F(RealUfsWriteBoosterControlLogicTest, ExplicitTrigger) {
  ASSERT_THAT(control_logic_.Reset(), IsOk());
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOff);

  EXPECT_THAT(control_logic_.Enable(), IsOk());

  // On->Off counter reset when over threshold
  for (int i = 0; i < 59; ++i) {
    EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOn);
    ASSERT_THAT(control_logic_.Update(under_threshold_delta_), IsOk());
  }
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOn);

  ASSERT_THAT(control_logic_.Update(over_threshold_delta_), IsOk());

  for (int i = 0; i < 3; ++i) {
    EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOn);
    ASSERT_THAT(control_logic_.Update(under_threshold_delta_), IsOk());
  }
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOn);

  ASSERT_THAT(control_logic_.Update(over_threshold_delta_), IsOk());

  // On->Off when under threshold for hysteresis, and another enable resets
  // counter.
  EXPECT_CALL(metrics_,
              SendPercentageToUMA(kExplicitWbBwUtilizationHistogram, 1))
      .Times(1);
  EXPECT_CALL(metrics_, SendToUMA(kExplicitWbOnCyclesHistogram, 183,
                                  kCyclesMinVal, kCyclesMaxVal, kCyclesBuckets))
      .Times(1);
  for (int i = 0; i < 59; ++i) {
    EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOn);
    ASSERT_THAT(control_logic_.Update(under_threshold_delta_), IsOk());
  }
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOn);

  EXPECT_THAT(control_logic_.Enable(), IsOk());

  for (int i = 0; i < 60; ++i) {
    EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOn);
    ASSERT_THAT(control_logic_.Update(under_threshold_delta_), IsOk());
  }
  EXPECT_THAT(binary_control_->Current().value(), BinaryControl::State::kOff);
}

}  // namespace discod
