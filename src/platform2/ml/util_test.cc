// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>
#include <optional>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <base/check.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/files/scoped_temp_dir.h>
#include <base/files/file_util.h>
#include <brillo/file_utils.h>

#include "ml/test_utils.h"
#include "ml/util.h"

namespace ml {
namespace {

// Represents a temp status file valid for the lifetime of this object.
// The constructor creates a temp file named "status" in a temp folder and
// writes `content` to that file.
// Use GetPath() to obtain the path fo the temporary file.
class ScopedTempStatusFile {
 public:
  explicit ScopedTempStatusFile(const std::string& content) {
    CHECK(dir_.CreateUniqueTempDir());
    file_path_ = dir_.GetPath().Append("status");
    CHECK(brillo::WriteStringToFile(file_path_, content));
  }
  ScopedTempStatusFile(const ScopedTempStatusFile&) = delete;
  ScopedTempStatusFile& operator=(const ScopedTempStatusFile&) = delete;

  base::FilePath GetPath() { return file_path_; }

 private:
  base::ScopedTempDir dir_;
  base::FilePath file_path_;
};

// Status file does not exist.
TEST(GetProcessMemoryUsageTest, InvalidFile) {
  ScopedTempStatusFile status_file("");
  MemoryUsage memory_usage;
  EXPECT_FALSE(GetProcessMemoryUsageFromFile(
      &memory_usage, status_file.GetPath().Append("nonexistfile")));
}

TEST(GetProcessMemoryUsageTest, EmptyFile) {
  ScopedTempStatusFile status_file("");
  MemoryUsage memory_usage;
  EXPECT_FALSE(
      GetProcessMemoryUsageFromFile(&memory_usage, status_file.GetPath()));
}

TEST(GetProcessMemoryUsageTest, MissingVmSwap) {
  ScopedTempStatusFile status_file("VmRSS: 3235 kB");
  MemoryUsage memory_usage;
  EXPECT_FALSE(
      GetProcessMemoryUsageFromFile(&memory_usage, status_file.GetPath()));
}

TEST(GetProcessMemoryUsageTest, MissingVmRSS) {
  ScopedTempStatusFile status_file("VmSwap: 34213 kB");
  MemoryUsage memory_usage;
  EXPECT_FALSE(
      GetProcessMemoryUsageFromFile(&memory_usage, status_file.GetPath()));
}

TEST(GetProcessMemoryUsageTest, MissingBothValues) {
  ScopedTempStatusFile status_file("VmRSS:  kB \n   VmSwap:  kB\n");
  MemoryUsage memory_usage;
  EXPECT_FALSE(
      GetProcessMemoryUsageFromFile(&memory_usage, status_file.GetPath()));
}

TEST(GetProcessMemoryUsageTest, MissingVmRSSValue) {
  ScopedTempStatusFile status_file("VmRSS: kB \n   VmSwap: 421532 kB\n");
  MemoryUsage memory_usage;
  EXPECT_FALSE(
      GetProcessMemoryUsageFromFile(&memory_usage, status_file.GetPath()));
}

TEST(GetProcessMemoryUsageTest, MissingVmSwapValue) {
  ScopedTempStatusFile status_file("VmRSS: 32432 kB \n   VmSwap: kB\n");
  MemoryUsage memory_usage;
  EXPECT_FALSE(
      GetProcessMemoryUsageFromFile(&memory_usage, status_file.GetPath()));
}

TEST(GetProcessMemoryUsageTest, InvalidVmSwapValueNan) {
  ScopedTempStatusFile status_file(
      "VmRSS:  767234322 kB \n   VmSwap: nan kB\n");
  MemoryUsage memory_usage;
  EXPECT_FALSE(
      GetProcessMemoryUsageFromFile(&memory_usage, status_file.GetPath()));
}

TEST(GetProcessMemoryUsageTest, InvalidVmRSSValueNan) {
  ScopedTempStatusFile status_file("VmRSS:  nan kB \n   VmSwap: 4214 kB\n");
  MemoryUsage memory_usage;
  EXPECT_FALSE(
      GetProcessMemoryUsageFromFile(&memory_usage, status_file.GetPath()));
}

TEST(GetProcessMemoryUsageTest, Duplicate) {
  ScopedTempStatusFile status_file(
      "VmRSS:  432 kB \n   VmSwap: 421532 kB\n"
      "VmRSS:  432 kB \n   VmSwap: 421532 kB\n");
  MemoryUsage memory_usage;
  EXPECT_FALSE(
      GetProcessMemoryUsageFromFile(&memory_usage, status_file.GetPath()));
}

TEST(GetProcessMemoryUsageTest, ValidInputNonZeroValue) {
  ScopedTempStatusFile status_file("VmRSS:  432 kB \n   VmSwap: 421532 kB\n");
  MemoryUsage memory_usage;
  EXPECT_TRUE(
      GetProcessMemoryUsageFromFile(&memory_usage, status_file.GetPath()));
  EXPECT_EQ(memory_usage.VmRSSKb, 432);
  EXPECT_EQ(memory_usage.VmSwapKb, 421532);
}

TEST(GetProcessMemoryUsageTest, ValidInputZeroValue) {
  ScopedTempStatusFile status_file("VmRSS:  0 kB \n   VmSwap: 0 kB\n");
  MemoryUsage memory_usage;
  EXPECT_TRUE(
      GetProcessMemoryUsageFromFile(&memory_usage, status_file.GetPath()));
  EXPECT_EQ(memory_usage.VmRSSKb, 0);
  EXPECT_EQ(memory_usage.VmSwapKb, 0);
}

TEST(GetProcessMemoryUsageTest, ValidInputZeroLead) {
  ScopedTempStatusFile status_file(
      "VmRSS:    0242 kB \n   VmSwap:    03523 kB\n");
  MemoryUsage memory_usage;
  EXPECT_TRUE(
      GetProcessMemoryUsageFromFile(&memory_usage, status_file.GetPath()));
  EXPECT_EQ(memory_usage.VmRSSKb, 242);
  EXPECT_EQ(memory_usage.VmSwapKb, 3523);
}

// Checks the maximum value of size_t. It may fail if treated as int32.
TEST(GetProcessMemoryUsageTest, ValidInputMaxSizeT) {
  constexpr size_t kSizeTMax = std::numeric_limits<size_t>::max();

  ScopedTempStatusFile status_file(base::StringPrintf(
      "VmRSS:   %zu kB\nVmSwap:    %zu kB\n", kSizeTMax, kSizeTMax));
  MemoryUsage memory_usage;
  EXPECT_TRUE(
      GetProcessMemoryUsageFromFile(&memory_usage, status_file.GetPath()));
  EXPECT_EQ(memory_usage.VmRSSKb, kSizeTMax);
  EXPECT_EQ(memory_usage.VmSwapKb, kSizeTMax);
}

TEST(GetProcessMemoryUsageTest, OrderChanged) {
  ScopedTempStatusFile status_file(
      "VmSwap:       34 kB\nVmRSS:        123 kB\n");
  MemoryUsage memory_usage;
  EXPECT_TRUE(
      GetProcessMemoryUsageFromFile(&memory_usage, status_file.GetPath()));
  EXPECT_EQ(memory_usage.VmRSSKb, 123);
  EXPECT_EQ(memory_usage.VmSwapKb, 34);
}

TEST(GetProcessMemoryUsageTest, MissingNonMemoryValue) {
  ScopedTempStatusFile status_file(
      "VmSize:          \nVmSwap:       34 kB\nVmRSS:        123 kB\n");
  MemoryUsage memory_usage;
  EXPECT_TRUE(
      GetProcessMemoryUsageFromFile(&memory_usage, status_file.GetPath()));
  EXPECT_EQ(memory_usage.VmRSSKb, 123);
  EXPECT_EQ(memory_usage.VmSwapKb, 34);
}

TEST(GetProcessMemoryUsageTest, RealisticProcStatus) {
  ScopedTempStatusFile status_file(
      "Name:   cat\n"
      "Umask:  0022\n"
      "State:  R (running)\n"
      "Tgid:   21255\n"
      "Ngid:   0\n"
      "Pid:    21255\n"
      "PPid:   7\n"
      "TracerPid:      0\n"
      "Uid:    694971  694971  694971  694971\n"
      "Gid:    89939   89939   89939   89939\n"
      "FDSize: 256\n"
      "Groups: 4 11 18 19 20 27 250 89939\n"
      "NStgid: 21255\n"
      "NSpid:  21255\n"
      "NSpgid: 21255\n"
      "NSsid:  0\n"
      "VmPeak:     6048 kB\n"
      "VmSize:     6048 kB\n"
      "VmLck:         0 kB\n"
      "VmPin:         0 kB\n"
      "VmHWM:       732 kB\n"
      "VmRSS:       732 kB\n"
      "RssAnon:              68 kB\n"
      "RssFile:             664 kB\n"
      "RssShmem:              0 kB\n"
      "VmData:      312 kB\n"
      "VmStk:       136 kB\n"
      "VmExe:        40 kB\n"
      "VmLib:      1872 kB\n"
      "VmPTE:        52 kB\n"
      "VmSwap:      321 kB\n"
      "HugetlbPages:          0 kB\n"
      "CoreDumping:    0\n"
      "Threads:        1\n"
      "SigQ:   0/767737\n"
      "SigPnd: 0000000000000000\n"
      "ShdPnd: 0000000000000000\n"
      "SigBlk: 0000000000000000\n"
      "SigIgn: 0000000001001000\n"
      "SigCgt: 0000000000000000\n"
      "CapInh: 0000000000000000\n"
      "CapPrm: 0000000000000000\n"
      "CapEff: 0000000000000000\n"
      "CapBnd: 0000003fffffffff\n"
      "CapAmb: 0000000000000000\n"
      "NoNewPrivs:     0\n"
      "Seccomp:        0\n"
      "Speculation_Store_Bypass:       thread vulnerable\n"
      "Cpus_allowed:   ff,ffffffff,ffffffff\n"
      "Cpus_allowed_list:      0-71\n"
      "Mems_allowed:   00000000,00000003\n"
      "Mems_allowed_list:      0-1\n"
      "voluntary_ctxt_switches:        0\n"
      "nonvoluntary_ctxt_switches:     1\n");
  MemoryUsage memory_usage;
  EXPECT_TRUE(
      GetProcessMemoryUsageFromFile(&memory_usage, status_file.GetPath()));
  EXPECT_EQ(memory_usage.VmRSSKb, 732);
  EXPECT_EQ(memory_usage.VmSwapKb, 321);
}

TEST(GetRealPathTest, VariousInputs) {
  // Store the current directory for this test.
  base::FilePath cd;
  base::GetCurrentDirectory(&cd);
  const std::string cd_str(cd.value());

  // Resolve current directory.
  const base::FilePath path_1(".");
  std::optional<base::FilePath> real_1 = GetRealPath(path_1);
  EXPECT_TRUE(real_1.has_value());
  EXPECT_EQ(cd_str, real_1.value().value());

  // Resolve absolute path.
  const base::FilePath temp_path_2("/tmp/getrealpathtest/dir2");
  base::CreateDirectory(temp_path_2);
  const base::FilePath path_2("/tmp/getrealpathtest/dir2/../");
  std::optional<base::FilePath> real_2 = GetRealPath(path_2);
  EXPECT_TRUE(real_2.has_value());
  EXPECT_EQ("/tmp/getrealpathtest", real_2.value().value());

  // Check non-existing path.
  const base::FilePath path_4("/run/imageloader/fake-dlc-foo/package/root/");
  std::optional<base::FilePath> real_4 = GetRealPath(path_4);
  EXPECT_FALSE(real_4.has_value());
}

}  // namespace
}  // namespace ml
