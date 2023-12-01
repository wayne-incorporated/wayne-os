// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>
#include <string>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <brillo/process/process.h>
#include <gtest/gtest.h>
#include <rootdev/rootdev.h>
#include "init/utils.h"

namespace {

// Commands for disk formatting utility sfdisk.
// Specify that partition table should use gpt format.
constexpr char kSfdiskPartitionTableTypeCommand[] = "label: gpt\n";
// Templates for partition command (size specified in number of sectors).
constexpr char kSfdiskCommandFormat[] = "size=1, type=%s, name=\"%s\"\n";
constexpr char kSfdiskCommandWithAttrsFormat[] =
    "size=1, type=%s, name=\"%s\", attrs=\"%s\"\n";

// UUIDs for various partition types in gpt partition tables.
constexpr char kKernelPartition[] = "FE3A2A5D-4F32-41A7-B725-ACCC3285A309";
constexpr char kRootPartition[] = "3CB8E202-3B7E-47DD-8A3C-7FF2A13CFCEC";
constexpr char kDataPartition[] = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
constexpr char kReservedPartition[] = "2E0A753D-9E48-43B0-8337-B15192CB1B5E";
constexpr char kRWFWPartition[] = "CAB6E88E-ABF3-4102-A07A-D4BB9BE3C1D3";
constexpr char kEFIPartition[] = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";

}  // namespace

// TODO(b/286154453): Appears to fail when host OS has md array.
TEST(GetRootDevice, DISABLED_NoStripPartition) {
  base::FilePath root_dev;
  char dev_path[PATH_MAX];
  int ret = rootdev(dev_path, sizeof(dev_path), true, false);
  EXPECT_EQ(!ret, utils::GetRootDevice(&root_dev, false));
  EXPECT_EQ(dev_path, root_dev.value());
}

TEST(ReadFileToInt, IntContents) {
  base::ScopedTempDir temp_dir_;
  ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  base::FilePath file = temp_dir_.GetPath().Append("file");
  ASSERT_TRUE(base::WriteFile(file, "1"));
  int output;
  EXPECT_EQ(utils::ReadFileToInt(file, &output), true);
  EXPECT_EQ(output, 1);
}

TEST(ReadFileToInt, StringContents) {
  base::ScopedTempDir temp_dir_;
  ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  base::FilePath file = temp_dir_.GetPath().Append("file");
  ASSERT_TRUE(base::WriteFile(file, "Not an int"));
  int output;
  EXPECT_EQ(utils::ReadFileToInt(file, &output), false);
}

class CgptTest : public testing::Test {
 protected:
  void SetUp() override {
    constexpr int kSectorSize = 512;
    constexpr int kSectorCount = 25 * 1024;

    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    test_image_path_ = temp_dir_.GetPath().Append("test.img");
    base::File test_image(test_image_path_,
                          base::File::FLAG_CREATE | base::File::FLAG_WRITE);
    ASSERT_TRUE(test_image.IsValid());
    ASSERT_GE(test_image.SetLength(kSectorSize * kSectorCount), 0);
    test_image.Close();

    base::FilePath sfdisk_input_path =
        temp_dir_.GetPath().Append("sfdisk_input");
    base::File sfdisk_input(sfdisk_input_path,
                            base::File::FLAG_CREATE | base::File::FLAG_WRITE);
    ASSERT_TRUE(sfdisk_input.IsValid());
    std::vector<std::string> sfdisk_commands{
        kSfdiskPartitionTableTypeCommand,
        base::StringPrintf(kSfdiskCommandFormat, kDataPartition, "STATE"),
        base::StringPrintf(kSfdiskCommandWithAttrsFormat, kKernelPartition,
                           "KERN-A", "GUID:49,56"),
        base::StringPrintf(kSfdiskCommandFormat, kRootPartition, "ROOT-A"),
        base::StringPrintf(kSfdiskCommandWithAttrsFormat, kKernelPartition,
                           "KERN-B", "GUID:48"),
        base::StringPrintf(kSfdiskCommandFormat, kRootPartition, "ROOT-B"),
        base::StringPrintf(kSfdiskCommandWithAttrsFormat, kKernelPartition,
                           "KERN-C", "GUID:52,53,54,55"),
        base::StringPrintf(kSfdiskCommandFormat, kRootPartition, "ROOT-C"),
        base::StringPrintf(kSfdiskCommandFormat, kDataPartition, "OEM"),
        base::StringPrintf(kSfdiskCommandFormat, kReservedPartition,
                           "reserved"),
        base::StringPrintf(kSfdiskCommandFormat, kReservedPartition,
                           "reserved"),
        base::StringPrintf(kSfdiskCommandFormat, kRWFWPartition, "RWFW"),
        base::StringPrintf(kSfdiskCommandFormat, kEFIPartition, "EFI-SYSTEM")};
    for (const std::string& command : sfdisk_commands) {
      EXPECT_EQ(
          sfdisk_input.WriteAtCurrentPos(command.c_str(), command.length()),
          command.length());
    }
    sfdisk_input.Close();

    // Build partition table on backing file.
    brillo::ProcessImpl sfdisk;
    sfdisk.AddArg("/sbin/sfdisk");
    sfdisk.AddArg(test_image_path_.value());
    sfdisk.RedirectInput(sfdisk_input_path.value());
    ASSERT_EQ(sfdisk.Run(), 0);
  }

  base::FilePath test_image_path_;

 private:
  base::ScopedTempDir temp_dir_;
};

TEST_F(CgptTest, FindInvalidPartitions) {
  EXPECT_EQ(utils::GetPartitionNumber(test_image_path_, ""), -1);
  EXPECT_EQ(utils::GetPartitionNumber(test_image_path_, "NONEXISTENT"), -1);
  // return -1 here because there are multiple partitions labeled "reserved".
  EXPECT_EQ(utils::GetPartitionNumber(test_image_path_, "reserved"), -1);
}

TEST_F(CgptTest, FindValidPartitions) {
  EXPECT_EQ(utils::GetPartitionNumber(test_image_path_, "STATE"), 1);
  EXPECT_EQ(utils::GetPartitionNumber(test_image_path_, "KERN-A"), 2);
  EXPECT_EQ(utils::GetPartitionNumber(test_image_path_, "ROOT-A"), 3);
  EXPECT_EQ(utils::GetPartitionNumber(test_image_path_, "KERN-B"), 4);
  EXPECT_EQ(utils::GetPartitionNumber(test_image_path_, "ROOT-B"), 5);
  EXPECT_EQ(utils::GetPartitionNumber(test_image_path_, "KERN-C"), 6);
  EXPECT_EQ(utils::GetPartitionNumber(test_image_path_, "ROOT-C"), 7);
  EXPECT_EQ(utils::GetPartitionNumber(test_image_path_, "OEM"), 8);
  EXPECT_EQ(utils::GetPartitionNumber(test_image_path_, "RWFW"), 11);
  EXPECT_EQ(utils::GetPartitionNumber(test_image_path_, "EFI-SYSTEM"), 12);
}

TEST_F(CgptTest, ReadPartitionMetadata) {
  bool successful;
  int priority;
  EXPECT_TRUE(utils::ReadPartitionMetadata(test_image_path_, 2, &successful,
                                           &priority));
  EXPECT_TRUE(successful);
  EXPECT_EQ(priority, 2);
  EXPECT_TRUE(utils::ReadPartitionMetadata(test_image_path_, 4, &successful,
                                           &priority));
  EXPECT_FALSE(successful);
  EXPECT_EQ(priority, 1);
  EXPECT_TRUE(utils::ReadPartitionMetadata(test_image_path_, 6, &successful,
                                           &priority));
  EXPECT_FALSE(successful);
  EXPECT_EQ(priority, 0);
}

TEST_F(CgptTest, EnsureKernelIsBootable) {
  utils::EnsureKernelIsBootable(test_image_path_, 4);
  bool successful;
  int priority;
  EXPECT_TRUE(utils::ReadPartitionMetadata(test_image_path_, 4, &successful,
                                           &priority));
  EXPECT_TRUE(successful);
  EXPECT_GT(priority, 0);

  utils::EnsureKernelIsBootable(test_image_path_, 6);
  EXPECT_TRUE(utils::ReadPartitionMetadata(test_image_path_, 6, &successful,
                                           &priority));
  EXPECT_TRUE(successful);
  EXPECT_GT(priority, 0);
}
