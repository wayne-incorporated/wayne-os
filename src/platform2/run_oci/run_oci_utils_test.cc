// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "run_oci/run_oci_utils.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

namespace run_oci {
namespace {

TEST(RunOciUtilsTest, TestOpenOciConfigSafely) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath config_file = temp_dir.GetPath().Append("config.json");

  // Call OpenOciConfigSafely when |config_file| does not exist (yet).
  // Verify it returns ENOENT.
  {
    brillo::SafeFD fd(OpenOciConfigSafely(config_file));
    EXPECT_FALSE(fd.is_valid());
  }

  // Create the file on a filesystem with exec. Verify OpenOciConfigSafely
  // works.
  const std::string content = "{}";
  ASSERT_EQ(content.size(),
            base::WriteFile(config_file, content.data(), content.size()));
  {
    // TODO(crbug/1090237): QEMU emulated boards seem to produce weird f_flag
    // for fstatvfs. Skip check ST_NOEXEC on ARM family unittest.
#if defined(ARCH_CPU_ARM_FAMILY)
    brillo::SafeFD fd(OpenOciConfigSafelyForTest(config_file, false));
#else
    brillo::SafeFD fd(OpenOciConfigSafely(config_file));
#endif
    EXPECT_TRUE(fd.is_valid());
    auto result = fd.ReadContents();
    ASSERT_FALSE(brillo::SafeFD::IsError(result.second));
    EXPECT_EQ(content, std::string(result.first.begin(), result.first.end()));
  }

  // Verify OpenOciConfigSafely returns EPERM when the file is not on an exec
  // filesystem.
  {
    // The QEMU emulator we use to run unit tests on simulated ARM boards does
    // not fully support statvfs(2). OpenOciConfigSafely's ST_NOEXEC check
    // doesn't work for that reason.
#if !defined(ARCH_CPU_ARM_FAMILY)
    errno = 0;
    brillo::SafeFD fd(OpenOciConfigSafely(base::FilePath("/proc/cpuinfo")));
    EXPECT_EQ(EPERM, errno);
    EXPECT_FALSE(fd.is_valid());
#endif
  }
}

}  // namespace
}  // namespace run_oci
