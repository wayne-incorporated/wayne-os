// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>
#include <stdint.h>

#include <string>

#include "diagnostics/base/file_test_utils.h"
#include "diagnostics/cros_healthd/utils/memory_info.h"

namespace diagnostics {
namespace {

class MemoryInfoTest : public BaseFileTest {
 protected:
  MemoryInfoTest() = default;
  MemoryInfoTest(const MemoryInfoTest&) = delete;
  MemoryInfoTest& operator=(const MemoryInfoTest&) = delete;

  void SetMockMemoryInfo(const std::string& info) {
    SetFile({"proc", "meminfo"}, info);
  }
};

TEST_F(MemoryInfoTest, MeminfoSuccess) {
  SetMockMemoryInfo(
      "MemTotal:        3906320 kB\n"
      "MemFree:         873180 kB\n"
      "MemAvailable:    87980 kB\n");

  auto memory_info = MemoryInfo::ParseFrom(root_dir());
  EXPECT_TRUE(memory_info.has_value());
  EXPECT_EQ(memory_info.value().total_memory_kib, 3906320);
  EXPECT_EQ(memory_info.value().free_memory_kib, 873180);
  EXPECT_EQ(memory_info.value().available_memory_kib, 87980);
}

TEST_F(MemoryInfoTest, MeminfoNoFile) {
  auto memory_info = MemoryInfo::ParseFrom(root_dir());
  EXPECT_FALSE(memory_info.has_value());
}

TEST_F(MemoryInfoTest, MeminfoFormattedIncorrectly) {
  SetMockMemoryInfo("Incorrectly formatted meminfo contents.\n");

  auto memory_info = MemoryInfo::ParseFrom(root_dir());
  EXPECT_FALSE(memory_info.has_value());
}

TEST_F(MemoryInfoTest, MeminfoNoMemTotal) {
  SetMockMemoryInfo(
      "MemFree:         873180 kB\n"
      "MemAvailable:    87980 kB\n");

  auto memory_info = MemoryInfo::ParseFrom(root_dir());
  EXPECT_FALSE(memory_info.has_value());
}

TEST_F(MemoryInfoTest, MeminfoNoMemFree) {
  SetMockMemoryInfo(
      "MemTotal:        3906320 kB\n"
      "MemAvailable:    87980 kB\n");

  auto memory_info = MemoryInfo::ParseFrom(root_dir());
  EXPECT_FALSE(memory_info.has_value());
}

TEST_F(MemoryInfoTest, MeminfoNoMemAvailable) {
  SetMockMemoryInfo(
      "MemTotal:        3906320 kB\n"
      "MemFree:         873180 kB\n");

  auto memory_info = MemoryInfo::ParseFrom(root_dir());
  EXPECT_FALSE(memory_info.has_value());
}

TEST_F(MemoryInfoTest, MeminfoIncorrectlyFormattedMemTotal) {
  // No space between memory amount and unit.
  SetMockMemoryInfo(
      "MemTotal:        3906320kB\n"
      "MemFree:         873180 kB\n"
      "MemAvailable:    87980 kB\n");

  auto memory_info = MemoryInfo::ParseFrom(root_dir());
  EXPECT_FALSE(memory_info.has_value());
}

TEST_F(MemoryInfoTest, MeminfoIncorrectlyFormattedMemFree) {
  SetMockMemoryInfo(
      "MemTotal:        3906320 kB\n"
      "MemFree:         873180 WrongUnit\n"
      "MemAvailable:    87980 kB\n");

  auto memory_info = MemoryInfo::ParseFrom(root_dir());
  EXPECT_FALSE(memory_info.has_value());
}

TEST_F(MemoryInfoTest, MeminfoIncorrectlyFormattedMemAvailable) {
  SetMockMemoryInfo(
      "MemTotal:        3906320 kB\n"
      "MemFree:         873180 kB\n"
      "MemAvailable:    NotAnInteger kB\n");

  auto memory_info = MemoryInfo::ParseFrom(root_dir());
  EXPECT_FALSE(memory_info.has_value());
}

}  // namespace
}  // namespace diagnostics
