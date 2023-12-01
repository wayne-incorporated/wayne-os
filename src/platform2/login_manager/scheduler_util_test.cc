// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/scheduler_util.h"

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

namespace login_manager {

namespace {

constexpr char kCpuBusDir[] = "sys/bus/cpu/devices";
constexpr char kCpuCapFile[] = "cpu_capacity";
constexpr char kCpuMaxFreqFile[] = "cpufreq/cpuinfo_max_freq";
constexpr char kCpuHighestPerfFile[] = "acpi_cppc/highest_perf";

constexpr const char* kHybridMaxFreqs[] = {
    "4400000", "4400000", "4400000", "4400000", "3300000", "3300000", "3300000",
    "3300000", "3300000", "3300000", "3300000", "3300000", "2100000", "2100000",
};
constexpr char kSmallCpuIdsFromHybridFreq[] = "10,11,12,13,4,5,6,7,8,9";
constexpr char kSmallCpuIdsNonHybridFreq[] = "";

constexpr const char* kNonHybridMaxFreqs[] = {
    "4400000", "4400000", "4400000", "4400000",
    "4400000", "4400000", "4400000", "4400000",
};

constexpr const char* kCapacities[] = {
    "598",
    "598",
    "1024",
    "1024",
};
constexpr char kSmallCpuIdsFromCap[] = "0,1";

constexpr const char* kHybridHighestPerfs[] = {"166", "166", "176", "176",
                                               "181", "181", "171", "171",
                                               "186", "186", "186", "186"};
constexpr char kSmallCpuIdsFromHighestPerf[] = "0,1,6,7";

}  // namespace

using SchedulerUtilTest = ::testing::Test;

void run_with_attr(const char* attrFile,
                   const base::span<const base::StringPiece> attributes,
                   const char* expectedCpuIds) {
  base::ScopedTempDir tmpdir;
  ASSERT_TRUE(tmpdir.CreateUniqueTempDir());
  base::FilePath test_dir = tmpdir.GetPath();

  int i = 0;
  for (const auto& attr : attributes) {
    base::FilePath relative_path(
        base::StringPrintf("%s/cpu%d/%s", kCpuBusDir, i, attrFile));
    base::FilePath attr_path = test_dir.Append(relative_path);
    base::File::Error error;
    ASSERT_TRUE(base::CreateDirectoryAndGetError(attr_path.DirName(), &error))
        << "Error creating directory: " << error;
    ASSERT_TRUE(base::WriteFile(attr_path, attr));
    i++;
  }

  std::vector<std::string> small_cpu_ids =
      login_manager::GetSmallCoreCpuIdsFromAttr(test_dir.Append(kCpuBusDir),
                                                attrFile);
  std::string small_cpu_mask = base::JoinString(small_cpu_ids, ",");
  EXPECT_EQ(small_cpu_mask, expectedCpuIds);
}

TEST_F(SchedulerUtilTest, TestSmallCoreCpuIdsFromCapacity) {
  const std::vector<const base::StringPiece> attributes(std::begin(kCapacities),
                                                        std::end(kCapacities));
  run_with_attr(kCpuCapFile, attributes, kSmallCpuIdsFromCap);
}

TEST_F(SchedulerUtilTest, TestSmallCoreCpuIdsFromFreqForHybrid) {
  const std::vector<const base::StringPiece> attributes(
      std::begin(kHybridMaxFreqs), std::end(kHybridMaxFreqs));
  run_with_attr(kCpuMaxFreqFile, attributes, kSmallCpuIdsFromHybridFreq);
}

TEST_F(SchedulerUtilTest, TestSmallCoreCpuIdsFromCppcForHybrid) {
  const std::vector<const base::StringPiece> attributes(
      std::begin(kHybridHighestPerfs), std::end(kHybridHighestPerfs));
  run_with_attr(kCpuHighestPerfFile, attributes, kSmallCpuIdsFromHighestPerf);
}

TEST_F(SchedulerUtilTest, TestSmallCoreCpuIdsFromFreqForNonHybrid) {
  const std::vector<const base::StringPiece> attributes(
      std::begin(kNonHybridMaxFreqs), std::end(kNonHybridMaxFreqs));
  run_with_attr(kCpuMaxFreqFile, attributes, kSmallCpuIdsNonHybridFreq);
}

}  // namespace login_manager
