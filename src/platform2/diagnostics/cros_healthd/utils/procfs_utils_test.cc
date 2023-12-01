// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/utils/procfs_utils.h"

#include <sys/types.h>

#include <base/files/file_path.h>
#include <gtest/gtest.h>

#include "diagnostics/base/file_test_utils.h"

namespace diagnostics {
namespace {

// Production instances will use a root directory of "/".
constexpr char kProductionRootDir[] = "/";

// Process ID to test with.
constexpr pid_t kProcessId = 42;

TEST(ProcfsUtilsTest, GetProcProcessDirectoryPath) {
  const auto process_dir = GetProcProcessDirectoryPath(
      base::FilePath(kProductionRootDir), kProcessId);
  EXPECT_EQ(process_dir.value(), "/proc/42");
}

TEST(ProcfsUtilsTest, GetProcCpuInfoPath) {
  const auto cpuinfo_path =
      GetProcCpuInfoPath(base::FilePath(kProductionRootDir));
  EXPECT_EQ(cpuinfo_path.value(), "/proc/cpuinfo");
}

TEST(ProcfsUtilsTest, GetProcStatPath) {
  const auto stat_path = GetProcStatPath(base::FilePath(kProductionRootDir));
  EXPECT_EQ(stat_path.value(), "/proc/stat");
}

TEST(ProcfsUtilsTest, GetProcUptimePath) {
  const auto uptime_path =
      GetProcUptimePath(base::FilePath(kProductionRootDir));
  EXPECT_EQ(uptime_path.value(), "/proc/uptime");
}

}  // namespace
}  // namespace diagnostics
