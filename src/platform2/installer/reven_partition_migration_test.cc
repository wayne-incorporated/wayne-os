// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <map>
#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/process/launch.h>
#include <base/test/scoped_chromeos_version_info.h>
#include <brillo/files/file_util.h>
#include <gtest/gtest.h>

#include "installer/inst_util.h"
#include "installer/mock_cgpt_manager.h"
#include "installer/mock_metrics.h"
#include "installer/reven_partition_migration.h"
#include "installer/reven_partition_migration_private.h"

using ::testing::_;
using ::testing::Eq;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::StrictMock;

namespace {

uint64_t MibToBytes(uint64_t mib) {
  return mib * 1024 * 1024;
}

// Use truncate to create a sparse file.
void TruncateFile(const base::FilePath& path, const std::string& size) {
  std::string output;
  EXPECT_TRUE(base::GetAppOutput(
      base::CommandLine({"truncate", "--size=" + size, path.value()}),
      &output));
}

struct ComparePartitionNum {
  bool operator()(const PartitionNum& a, const PartitionNum& b) const {
    return a.Value() < b.Value();
  }
};

class MockEnvironment : public base::Environment {
 public:
  MOCK_METHOD(bool,
              GetVar,
              (base::StringPiece variable_name, std::string* result),
              (override));
  MOCK_METHOD(bool, HasVar, (base::StringPiece variable_name), (override));
  MOCK_METHOD(bool,
              SetVar,
              (base::StringPiece variable_name, const std::string& new_value),
              (override));
  MOCK_METHOD(bool, UnSetVar, (base::StringPiece variable_name), (override));
};

class PartitionMigrationTest : public ::testing::Test {
 protected:
  void SetUp() {
    EXPECT_TRUE(tmp_dir_.CreateUniqueTempDir());
    disk_path_ = tmp_dir_.GetPath().Append("disk");
    TruncateFile(disk_path_, "10GiB");

    EXPECT_CALL(cgpt_manager_, DeviceName())
        .WillRepeatedly(ReturnRef(disk_path_));

    // Numbers from a reven 113 install (`cgpt show`).
    orig_partitions_[PartitionNum::KERN_A] = {69, 32768};
    orig_partitions_[PartitionNum::ROOT_A] = {8884224, 8388608};
    orig_partitions_[PartitionNum::KERN_B] = {32837, 32768};
    orig_partitions_[PartitionNum::ROOT_B] = {495616, 8388608};

    // Write some to the kernel partitions to validate it gets copied
    // properly.
    InitializeKernelData();
    WriteKernelData(orig_partitions_[PartitionNum::KERN_A].start);
    WriteKernelData(orig_partitions_[PartitionNum::KERN_B].start);

    EXPECT_CALL(cgpt_manager_, GetSectorRange(_, _))
        .WillRepeatedly(Invoke(this, &PartitionMigrationTest::GetSectorRange));
  }

  // Write the 16MiB test kernel data to the fake disk, beginning at
  // `start_sector`.
  void WriteKernelData(uint64_t start_sector) {
    base::File disk_file(disk_path_,
                         base::File::FLAG_OPEN | base::File::FLAG_WRITE);
    EXPECT_TRUE(
        disk_file.WriteAndCheck(SectorsToBytes(start_sector), kernel_data_));
  }

  // Check that the new kernel partition's data was properly initialized.
  void CheckNewKernelData(PartitionNum kern_num) {
    PartitionNum root_num(kern_num.Value() + 1);
    base::File disk_file(disk_path_,
                         base::File::FLAG_OPEN | base::File::FLAG_READ);
    std::vector<uint8_t> new_kernel_data;
    new_kernel_data.resize(MibToBytes(64));
    EXPECT_TRUE(disk_file.ReadAndCheck(
        SectorsToBytes(orig_partitions_[root_num].start +
                       orig_partitions_[root_num].count - MibToSectors(64)),
        new_kernel_data));

    std::vector<uint8_t> expected_kernel_data = kernel_data_;
    expected_kernel_data.resize(new_kernel_data.size(), 0);
    EXPECT_EQ(new_kernel_data, expected_kernel_data);
  }

  void ExpectMetric(PartitionMigrationResult result) {
    EXPECT_CALL(metrics_, SendEnumMetric(_, static_cast<int>(result), _))
        .WillOnce(Return(true));
  }

  void SetIsInstall(bool is_install) {
    EXPECT_CALL(env_, HasVar(base::StringPiece(kEnvIsInstall)))
        .WillOnce(Return(is_install));
  }

  void ExpectSlotAMigration() {
    SectorRange root_a = orig_partitions_[PartitionNum::ROOT_A];

    // Kernel is now the last 64MiB of the original root partition.
    EXPECT_CALL(cgpt_manager_, SetSectorRange(PartitionNum::KERN_A,
                                              Eq(root_a.start + root_a.count -
                                                 MibToSectors(64)),
                                              Eq(MibToSectors(64))))
        .WillOnce(Return(CgptErrorCode::kSuccess));
    EXPECT_CALL(cgpt_manager_,
                SetSectorRange(PartitionNum::ROOT_A, Eq(std::nullopt),
                               Eq(root_a.count - MibToSectors(64))))
        .WillOnce(Return(CgptErrorCode::kSuccess));
  }

  void ExpectSlotBMigration() {
    SectorRange root_b = orig_partitions_[PartitionNum::ROOT_B];

    // Kernel is now the last 64MiB of the original root partition.
    EXPECT_CALL(cgpt_manager_, SetSectorRange(PartitionNum::KERN_B,
                                              Eq(root_b.start + root_b.count -
                                                 MibToSectors(64)),
                                              Eq(MibToSectors(64))))
        .WillOnce(Return(CgptErrorCode::kSuccess));
    EXPECT_CALL(cgpt_manager_,
                SetSectorRange(PartitionNum::ROOT_B, Eq(std::nullopt),
                               Eq(root_b.count - MibToSectors(64))))
        .WillOnce(Return(CgptErrorCode::kSuccess));
  }

  base::ScopedTempDir tmp_dir_;
  base::FilePath disk_path_;
  std::map<PartitionNum, SectorRange, ComparePartitionNum> orig_partitions_;

  // Use StrictMock for cgpt_manager because we care about not having
  // any unexpected calls that modify the disk. Also use StrictMock for
  // the other interfaces, since they are very minimal and unlikely to
  // break.
  StrictMock<MockCgptManager> cgpt_manager_;
  StrictMock<MockEnvironment> env_;
  StrictMock<MockMetrics> metrics_;

 private:
  void InitializeKernelData() {
    kernel_data_.resize(MibToBytes(16));  // 16MiB

    uint8_t val = 1;
    for (uint8_t& byte : kernel_data_) {
      byte = val;
      val++;
    }
  }

  CgptErrorCode GetSectorRange(PartitionNum num, SectorRange& sectors) {
    const auto it = orig_partitions_.find(num);
    if (it == orig_partitions_.end()) {
      return CgptErrorCode::kUnknownError;
    }

    sectors = it->second;
    return CgptErrorCode::kSuccess;
  }

  std::vector<uint8_t> kernel_data_;
};

}  // namespace

// Tests for errors in creating a `SlotPlan`:

TEST_F(PartitionMigrationTest, SlotPlanInitializeGptReadKernError) {
  orig_partitions_.erase(PartitionNum::KERN_A);

  SlotPlan slot_plan = SlotPlan::ForSlotA(cgpt_manager_);
  EXPECT_EQ(slot_plan.Initialize(),
            PartitionMigrationResult::kGptReadKernError);
}

TEST_F(PartitionMigrationTest, SlotPlanInitializeGptReadRootError) {
  orig_partitions_.erase(PartitionNum::ROOT_A);

  SlotPlan slot_plan = SlotPlan::ForSlotA(cgpt_manager_);
  EXPECT_EQ(slot_plan.Initialize(),
            PartitionMigrationResult::kGptReadRootError);
}

TEST_F(PartitionMigrationTest, SlotPlanInitializeRootUnexpectedSize) {
  orig_partitions_[PartitionNum::ROOT_A].count = MibToSectors(3047);

  SlotPlan slot_plan = SlotPlan::ForSlotA(cgpt_manager_);
  EXPECT_EQ(slot_plan.Initialize(),
            PartitionMigrationResult::kRootPartitionUnexpectedSize);
}

TEST_F(PartitionMigrationTest, SlotPlanInitializeNoMigrationNeeded) {
  orig_partitions_[PartitionNum::KERN_A].count = MibToSectors(64);

  SlotPlan slot_plan = SlotPlan::ForSlotA(cgpt_manager_);
  EXPECT_EQ(slot_plan.Initialize(),
            PartitionMigrationResult::kNoMigrationNeeded);
}

// Tests for errors when running a migration on one slot:

TEST_F(PartitionMigrationTest, SlotPlanRunDiskOpenError) {
  EXPECT_TRUE(brillo::DeleteFile(disk_path_));

  SlotPlan slot_plan = SlotPlan::ForSlotA(cgpt_manager_);
  EXPECT_EQ(slot_plan.Initialize(), PartitionMigrationResult::kSuccess);
  EXPECT_EQ(slot_plan.Run(), PartitionMigrationResult::kDiskOpenError);
}

TEST_F(PartitionMigrationTest, SlotPlanRunDiskReadError) {
  EXPECT_TRUE(base::WriteFile(disk_path_, ""));

  SlotPlan slot_plan = SlotPlan::ForSlotA(cgpt_manager_);
  EXPECT_EQ(slot_plan.Initialize(), PartitionMigrationResult::kSuccess);
  EXPECT_EQ(slot_plan.Run(), PartitionMigrationResult::kDiskReadError);
}

TEST_F(PartitionMigrationTest, SlotPlanRunGptWriteRootError) {
  EXPECT_CALL(cgpt_manager_, SetSectorRange(PartitionNum::ROOT_A, _, _))
      .WillOnce(Return(CgptErrorCode::kUnknownError));

  SlotPlan slot_plan = SlotPlan::ForSlotA(cgpt_manager_);
  EXPECT_EQ(slot_plan.Initialize(), PartitionMigrationResult::kSuccess);
  EXPECT_EQ(slot_plan.Run(), PartitionMigrationResult::kGptWriteRootError);
}

TEST_F(PartitionMigrationTest, SlotPlanRunGptWriteKernError) {
  EXPECT_CALL(cgpt_manager_, SetSectorRange(PartitionNum::ROOT_A, _, _))
      .WillOnce(Return(CgptErrorCode::kSuccess));
  EXPECT_CALL(cgpt_manager_, SetSectorRange(PartitionNum::KERN_A, _, _))
      .WillOnce(Return(CgptErrorCode::kUnknownError));

  SlotPlan slot_plan = SlotPlan::ForSlotA(cgpt_manager_);
  EXPECT_EQ(slot_plan.Initialize(), PartitionMigrationResult::kSuccess);
  EXPECT_EQ(slot_plan.Run(), PartitionMigrationResult::kGptWriteKernError);
}

// Note: no test for kDiskWriteError, since it's difficult to force a
// write error to occur in a test without also making the file open
// fail.

// Tests for a successful migration of one or both slots:

TEST_F(PartitionMigrationTest, RunSuccess) {
  SetIsInstall(true);
  ExpectSlotAMigration();
  ExpectSlotBMigration();
  ExpectMetric(PartitionMigrationResult::kSuccess);

  EXPECT_TRUE(RunRevenPartitionMigration(cgpt_manager_, metrics_, env_));

  CheckNewKernelData(PartitionNum::KERN_A);
  CheckNewKernelData(PartitionNum::KERN_B);
}

TEST_F(PartitionMigrationTest, RunSuccessCloudReady96) {
  SetIsInstall(true);

  // Numbers from a beerover 96.4 install (`cgpt show`).
  orig_partitions_[PartitionNum::KERN_A] = {20480, 32768};
  orig_partitions_[PartitionNum::ROOT_A] = {6623232, 6242304};
  orig_partitions_[PartitionNum::KERN_B] = {53248, 32768};
  orig_partitions_[PartitionNum::ROOT_B] = {380928, 6242304};

  WriteKernelData(orig_partitions_[PartitionNum::KERN_A].start);
  WriteKernelData(orig_partitions_[PartitionNum::KERN_B].start);

  ExpectSlotAMigration();
  ExpectSlotBMigration();
  ExpectMetric(PartitionMigrationResult::kSuccess);

  EXPECT_TRUE(RunRevenPartitionMigration(cgpt_manager_, metrics_, env_));

  CheckNewKernelData(PartitionNum::KERN_A);
  CheckNewKernelData(PartitionNum::KERN_B);
}

TEST_F(PartitionMigrationTest, RunNoMigrationNeeded) {
  SetIsInstall(true);
  orig_partitions_[PartitionNum::KERN_A].count = MibToSectors(64);
  orig_partitions_[PartitionNum::KERN_B].count = MibToSectors(64);

  ExpectMetric(PartitionMigrationResult::kNoMigrationNeeded);
  EXPECT_TRUE(RunRevenPartitionMigration(cgpt_manager_, metrics_, env_));
}

TEST_F(PartitionMigrationTest, RunSlotANoMigrationNeeded) {
  SetIsInstall(true);
  orig_partitions_[PartitionNum::KERN_A].count = MibToSectors(64);

  ExpectSlotBMigration();

  ExpectMetric(PartitionMigrationResult::kSuccess);
  EXPECT_TRUE(RunRevenPartitionMigration(cgpt_manager_, metrics_, env_));
}

TEST_F(PartitionMigrationTest, RunSlotBNoMigrationNeeded) {
  SetIsInstall(true);
  orig_partitions_[PartitionNum::KERN_B].count = MibToSectors(64);

  ExpectSlotAMigration();

  ExpectMetric(PartitionMigrationResult::kSuccess);
  EXPECT_TRUE(RunRevenPartitionMigration(cgpt_manager_, metrics_, env_));
}

// Tests for how errors are handled if either slot plan fails to
// initialize. An error metric should be sent, but postinstall should be
// allowed to proceed (RunRevenPartitionMigration returns true).

TEST_F(PartitionMigrationTest, RunSlotAPlanError) {
  SetIsInstall(true);
  orig_partitions_.erase(PartitionNum::KERN_A);

  ExpectMetric(PartitionMigrationResult::kGptReadKernError);
  EXPECT_TRUE(RunRevenPartitionMigration(cgpt_manager_, metrics_, env_));
}

TEST_F(PartitionMigrationTest, RunSlotBPlanError) {
  SetIsInstall(true);
  orig_partitions_.erase(PartitionNum::KERN_B);

  ExpectMetric(PartitionMigrationResult::kGptReadKernError);
  EXPECT_TRUE(RunRevenPartitionMigration(cgpt_manager_, metrics_, env_));
}

// Tests for propagating errors if either slot migration fails:

TEST_F(PartitionMigrationTest, RunSlotAMigrationError) {
  SetIsInstall(true);

  // Arbitrary choice of failure in the slot A migration.
  EXPECT_CALL(cgpt_manager_, SetSectorRange(PartitionNum::ROOT_A, _, _))
      .WillOnce(Return(CgptErrorCode::kUnknownError));

  ExpectMetric(PartitionMigrationResult::kGptWriteRootError);
  EXPECT_FALSE(RunRevenPartitionMigration(cgpt_manager_, metrics_, env_));
}

TEST_F(PartitionMigrationTest, RunSlotBMigrationError) {
  SetIsInstall(true);

  // Arbitrary choice of failure in the slot B migration.
  EXPECT_CALL(cgpt_manager_, SetSectorRange(PartitionNum::ROOT_B, _, _))
      .WillOnce(Return(CgptErrorCode::kUnknownError));

  // The Slot A migration has already happened by the time we get to the
  // failure on the B slot.
  ExpectSlotAMigration();

  ExpectMetric(PartitionMigrationResult::kGptWriteRootError);
  EXPECT_FALSE(RunRevenPartitionMigration(cgpt_manager_, metrics_, env_));
}

// Test that no migration occurs during updates (except on particular
// channels). This behavior will change in the future, but for now we
// only run the migration on install.
TEST_F(PartitionMigrationTest, NotRunningFromInstaller) {
  SetIsInstall(false);
  ExpectMetric(PartitionMigrationResult::kMigrationNotAllowed);
  EXPECT_TRUE(RunRevenPartitionMigration(cgpt_manager_, metrics_, env_));
}

// Test that migration planning does occur during updates, even if the
// migration doesn't run.
TEST_F(PartitionMigrationTest, UpdatePlanningOccurs) {
  SetIsInstall(false);

  orig_partitions_[PartitionNum::KERN_A].count = MibToSectors(64);
  orig_partitions_[PartitionNum::KERN_B].count = MibToSectors(64);

  ExpectMetric(PartitionMigrationResult::kNoMigrationNeeded);
  EXPECT_TRUE(RunRevenPartitionMigration(cgpt_manager_, metrics_, env_));
}

// Test that migration runs during updates when the payload is a test image.
TEST_F(PartitionMigrationTest, UpdateMigrationOnTest) {
  base::test::ScopedChromeOSVersionInfo scoped_info(
      "CHROMEOS_RELEASE_TRACK=testimage-channel\n", base::Time::Now());

  SetIsInstall(false);

  ExpectSlotAMigration();
  ExpectSlotBMigration();
  ExpectMetric(PartitionMigrationResult::kSuccess);

  EXPECT_TRUE(RunRevenPartitionMigration(cgpt_manager_, metrics_, env_));

  CheckNewKernelData(PartitionNum::KERN_A);
  CheckNewKernelData(PartitionNum::KERN_B);
}

// Test that migration runs during updates when the payload is on canary.
TEST_F(PartitionMigrationTest, UpdateMigrationOnCanary) {
  base::test::ScopedChromeOSVersionInfo scoped_info(
      "CHROMEOS_RELEASE_TRACK=canary-channel\n", base::Time::Now());

  SetIsInstall(false);

  ExpectSlotAMigration();
  ExpectSlotBMigration();
  ExpectMetric(PartitionMigrationResult::kSuccess);

  EXPECT_TRUE(RunRevenPartitionMigration(cgpt_manager_, metrics_, env_));

  CheckNewKernelData(PartitionNum::KERN_A);
  CheckNewKernelData(PartitionNum::KERN_B);
}

TEST(PartitionMigration, MibToSectors) {
  EXPECT_EQ(MibToSectors(0), 0);
  EXPECT_EQ(MibToSectors(1), 2048);
  EXPECT_EQ(MibToSectors(4096), 8388608);
}

TEST(PartitionMigration, SectorsToBytes) {
  EXPECT_EQ(SectorsToBytes(0), 0);
  EXPECT_EQ(SectorsToBytes(1), 512);
  EXPECT_EQ(SectorsToBytes(4096), 2097152);
}
