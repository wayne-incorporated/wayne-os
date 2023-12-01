// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <spaced/calculator/stateful_free_space_calculator.h>

#include <memory>
#include <string>
#include <vector>

#include <sys/statvfs.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/strings/stringprintf.h>
#include <base/task/sequenced_task_runner.h>
#include "base/test/task_environment.h"
#include <base/task/thread_pool.h>
#include <brillo/blkdev_utils/mock_lvm.h>

using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;

namespace spaced {
namespace {
// ~80% of blocks are allocated.
constexpr const char kSampleReport[] =
    "0 32768 thin-pool 3 20/24 200/256 - rw discard_passdown "
    "queue_if_no_space - 1024";

class StatefulFreeSpaceCalculatorMock : public StatefulFreeSpaceCalculator {
 public:
  StatefulFreeSpaceCalculatorMock(
      struct statvfs st,
      scoped_refptr<base::SequencedTaskRunner> task_runner,
      int64_t time_delta_seconds,
      std::optional<brillo::Thinpool> thinpool,
      base::RepeatingCallback<void(const StatefulDiskSpaceUpdate&)> signal)
      : StatefulFreeSpaceCalculator(
            task_runner, time_delta_seconds, thinpool, signal),
        st_(st) {}

 protected:
  int StatVFS(const base::FilePath& path, struct statvfs* st) override {
    memcpy(st, &st_, sizeof(struct statvfs));
    return !st_.f_fsid;
  }

 private:
  struct statvfs st_;
};

}  // namespace

class StatefulFreeSpaceCalculatorTest : public testing::Test {
 public:
  StatefulFreeSpaceCalculatorTest() = default;
  ~StatefulFreeSpaceCalculatorTest() override = default;
  StatefulFreeSpaceCalculatorTest(const StatefulFreeSpaceCalculatorTest&) =
      delete;
  StatefulFreeSpaceCalculatorTest& operator=(
      const StatefulFreeSpaceCalculatorTest&) = delete;

  scoped_refptr<base::SequencedTaskRunner> GetTestThreadRunner() {
    return task_environment_.GetMainThreadTaskRunner();
  }

  base::RepeatingCallback<void(const StatefulDiskSpaceUpdate&)>
  GetEmptyCallback() {
    return base::BindRepeating([](const StatefulDiskSpaceUpdate&) {});
  }

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY,
      base::test::TaskEnvironment::MainThreadType::IO};
};

TEST_F(StatefulFreeSpaceCalculatorTest, StatVfsError) {
  struct statvfs st = {};

  StatefulFreeSpaceCalculatorMock calculator(st, GetTestThreadRunner(), 0,
                                             std::nullopt, GetEmptyCallback());

  calculator.UpdateSize();
  EXPECT_EQ(calculator.GetSize(), -1);
}

TEST_F(StatefulFreeSpaceCalculatorTest, NoThinpoolCalculator) {
  struct statvfs st = {
      .f_frsize = 4096, .f_blocks = 2048, .f_bavail = 1024, .f_fsid = 1};

  StatefulFreeSpaceCalculatorMock calculator(st, GetTestThreadRunner(), 0,
                                             std::nullopt, GetEmptyCallback());

  calculator.UpdateSize();
  EXPECT_EQ(calculator.GetSize(), 4194304);
}

TEST_F(StatefulFreeSpaceCalculatorTest, ThinpoolCalculator) {
  struct statvfs st = {
      .f_frsize = 4096, .f_blocks = 2048, .f_bavail = 1024, .f_fsid = 1};

  auto lvm_command_runner = std::make_shared<brillo::MockLvmCommandRunner>();
  brillo::Thinpool thinpool("thinpool", "STATEFUL", lvm_command_runner);

  std::vector<std::string> cmd = {"/sbin/dmsetup", "status", "--noflush",
                                  "STATEFUL-thinpool-tpool"};

  std::string report = kSampleReport;
  EXPECT_CALL(*lvm_command_runner.get(), RunProcess(cmd, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(report), Return(true)));

  StatefulFreeSpaceCalculatorMock calculator(st, GetTestThreadRunner(), 0,
                                             thinpool, GetEmptyCallback());

  calculator.UpdateSize();
  EXPECT_EQ(calculator.GetSize(), 3669177);
}

TEST_F(StatefulFreeSpaceCalculatorTest, SignalStatefulDiskSpaceUpdate) {
  int64_t free_disk_space = -1;
  StatefulDiskSpaceState status = StatefulDiskSpaceState::NORMAL;

  base::RepeatingCallback callback = base::BindRepeating(
      [](int64_t* free_disk_space, StatefulDiskSpaceState* status,
         const StatefulDiskSpaceUpdate& state) {
        *free_disk_space = state.free_space_bytes();
        *status = state.state();
      },
      &free_disk_space, &status);

  struct statvfs st = {
      .f_frsize = 4096, .f_blocks = 2048, .f_bavail = 1024, .f_fsid = 1};

  auto lvm_command_runner = std::make_shared<brillo::MockLvmCommandRunner>();
  brillo::Thinpool thinpool("thinpool", "STATEFUL", lvm_command_runner);

  std::vector<std::string> cmd = {"/sbin/dmsetup", "status", "--noflush",
                                  "STATEFUL-thinpool-tpool"};

  std::string report = kSampleReport;
  EXPECT_CALL(*lvm_command_runner.get(), RunProcess(cmd, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(report), Return(true)));

  StatefulFreeSpaceCalculatorMock calculator(st, GetTestThreadRunner(), 0,
                                             thinpool, callback);
  calculator.UpdateSizeAndSignal();
  EXPECT_EQ(calculator.GetSize(), 3669177);
  EXPECT_EQ(free_disk_space, 3669177);
  EXPECT_EQ(status, StatefulDiskSpaceState::CRITICAL);
}

}  // namespace spaced
