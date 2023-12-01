// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <inttypes.h>
#include <utime.h>

#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <base/at_exit.h>
#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>

#include "metrics/metrics_daemon.h"
#include "metrics/metrics_library_mock.h"
#include "metrics/persistent_integer_mock.h"
#include "metrics/vmlog_writer.h"

using base::FilePath;
using base::StringPrintf;
using base::Time;
using base::TimeDelta;
using base::TimeTicks;
using std::string;
using std::vector;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::AtLeast;
using ::testing::Return;
using ::testing::StrictMock;

namespace chromeos_metrics {

TEST(VmlogWriterTest, ParseVmStats) {
  const char kVmStats[] =
      "pswpin 1345\n"
      "pswpout 8896\n"
      "foo 100\n"
      "bar 200\n"
      "pgmajfault 42\n"
      "pgmajfault_a 3838\n"
      "pgmajfault_f 66\n"
      "etcetc 300\n";
  std::istringstream input_stream(kVmStats);
  struct VmstatRecord stats;
  EXPECT_TRUE(VmStatsParseStats(&input_stream, &stats));
  EXPECT_EQ(stats.page_faults_, 42);
  EXPECT_EQ(stats.anon_page_faults_, 3838);
  EXPECT_EQ(stats.file_page_faults_, 66);
  EXPECT_EQ(stats.swap_in_, 1345);
  EXPECT_EQ(stats.swap_out_, 8896);
}

TEST(VmlogWriterTest, ParseVmStatsOptionalMissing) {
  const char kVmStats[] =
      "pswpin 1345\n"
      "pswpout 8896\n"
      "foo 100\n"
      "bar 200\n"
      "pgmajfault 42\n"
      // pgmajfault_a and pgmajfault_f are optional.
      // The default value when missing is 0.
      // "pgmajfault_a 3838\n"
      // "pgmajfault_f 66\n"
      "etcetc 300\n";
  std::istringstream input_stream(kVmStats);
  struct VmstatRecord stats;
  EXPECT_TRUE(VmStatsParseStats(&input_stream, &stats));
  EXPECT_EQ(stats.anon_page_faults_, 0);
  EXPECT_EQ(stats.file_page_faults_, 0);
}

// For mocking sysfs info.
class TestGpuInfo : public GpuInfo {
 public:
  TestGpuInfo(std::unique_ptr<std::istream> gpu_info_stream,
              GpuInfo::GpuType gpu_type)
      : GpuInfo(std::move(gpu_info_stream), gpu_type) {}
};

TEST(VmlogWriterTest, ParseAmdgpuFrequency) {
  const char kAmdgpuSclkFrequency[] =
      "0: 200Mhz\n"
      "1: 300Mhz\n"
      "2: 400Mhz *\n"
      "3: 480Mhz\n"
      "4: 553Mhz\n"
      "5: 626Mhz\n"
      "6: 685Mhz\n"
      "7: 720Mhz\n";
  auto input_stream =
      std::make_unique<std::istringstream>(kAmdgpuSclkFrequency);
  std::stringstream selected_frequency;

  TestGpuInfo gpu_info(std::move(input_stream), GpuInfo::GpuType::kAmd);

  EXPECT_TRUE(gpu_info.GetCurrentFrequency(selected_frequency));
  EXPECT_EQ(selected_frequency.str(), " 400");
}

TEST(VmlogWriterTest, ParseAmdgpuFrequencyMissing) {
  const char kAmdgpuSclkFrequency[] =
      "0: 200Mhz\n"
      "1: 300Mhz\n"
      "2: 400Mhz\n"
      "3: 480Mhz\n"
      "4: 553Mhz\n"
      "5: 626Mhz\n"
      "6: 685Mhz\n"
      "7: 720Mhz\n";
  auto input_stream =
      std::make_unique<std::istringstream>(kAmdgpuSclkFrequency);
  std::stringstream selected_frequency;

  TestGpuInfo gpu_info(std::move(input_stream), GpuInfo::GpuType::kAmd);

  EXPECT_FALSE(gpu_info.GetCurrentFrequency(selected_frequency));
  EXPECT_EQ(selected_frequency.str(), "");
}

TEST(VmlogWriterTest, ParseIntelgpuFrequency) {
  const char kIntelI915FrequencyInfo[] = R"(
PM IER=0x00000070 IMR=0xffffff8f ISR=0x00000000 IIR=0x00000000, MASK=0x00003fde
GT_PERF_STATUS: 0x00000000
Current freq: 100 MHz
Actual freq: 100 MHz
Idle freq: 100 MHz
Min freq: 100 MHz
)";
  auto input_stream =
      std::make_unique<std::istringstream>(kIntelI915FrequencyInfo);
  std::stringstream selected_frequency;

  TestGpuInfo gpu_info(std::move(input_stream), GpuInfo::GpuType::kIntel);

  EXPECT_TRUE(gpu_info.GetCurrentFrequency(selected_frequency));
  EXPECT_EQ(selected_frequency.str(), " 100");
}

TEST(VmlogWriterTest, ParseIntelgpuFrequencyMissing) {
  const char kIntelI915FrequencyInfo[] = R"()";
  auto input_stream =
      std::make_unique<std::istringstream>(kIntelI915FrequencyInfo);
  std::stringstream selected_frequency;

  TestGpuInfo gpu_info(std::move(input_stream), GpuInfo::GpuType::kIntel);

  EXPECT_FALSE(gpu_info.GetCurrentFrequency(selected_frequency));
  EXPECT_EQ(selected_frequency.str(), "");
}

TEST(VmlogWriterTest, ParseCpuTime) {
  const char kProcStat[] =
      "cpu  9440559 4101628 4207468 764635735 5162045 0 132368 0 0 0";
  std::istringstream input_stream(kProcStat);
  struct CpuTimeRecord record;
  EXPECT_TRUE(ParseCpuTime(&input_stream, &record));
  EXPECT_EQ(record.non_idle_time_, 17882023);
  EXPECT_EQ(record.total_time_, 787679803);
}

TEST(VmlogWriterTest, VmlogRotation) {
  base::FilePath temp_directory;
  EXPECT_TRUE(base::CreateNewTempDirectory("", &temp_directory));

  base::FilePath log_path = temp_directory.Append("log");
  base::FilePath rotated_path = temp_directory.Append("rotated");
  base::FilePath latest_symlink_path = temp_directory.Append("vmlog.1.LATEST");
  base::FilePath previous_symlink_path =
      temp_directory.Append("vmlog.1.PREVIOUS");

  // VmlogFile expects to create its output files.
  base::DeleteFile(log_path);
  base::DeleteFile(rotated_path);

  std::string header_string("header\n");
  VmlogFile l(log_path, rotated_path, 500, header_string);

  EXPECT_FALSE(base::PathExists(latest_symlink_path));

  std::string x_400(400, 'x');
  EXPECT_TRUE(l.Write(x_400));

  std::string buf;
  EXPECT_TRUE(base::ReadFileToString(log_path, &buf));
  EXPECT_EQ(header_string.size() + x_400.size(), buf.size());
  EXPECT_FALSE(base::ReadFileToString(rotated_path, &buf));

  std::string y_200(200, 'y');
  EXPECT_TRUE(l.Write(y_200));

  EXPECT_TRUE(base::ReadFileToString(log_path, &buf));
  EXPECT_EQ(header_string.size() + y_200.size(), buf.size());
  EXPECT_TRUE(base::ReadFileToString(rotated_path, &buf));
  EXPECT_EQ(header_string.size() + x_400.size(), buf.size());

  EXPECT_TRUE(base::PathExists(latest_symlink_path));
  base::FilePath symlink_target;
  EXPECT_TRUE(base::ReadSymbolicLink(latest_symlink_path, &symlink_target));
  EXPECT_EQ(rotated_path.value(), symlink_target.value());

  // Test log rotation for vmlog.1 files when a writer is created.
  // We use a zero log_interval to prevent writes from happening.
  EXPECT_TRUE(base::PathExists(latest_symlink_path));
  EXPECT_FALSE(base::PathExists(previous_symlink_path));

  VmlogWriter writer(temp_directory, base::TimeDelta());
  EXPECT_FALSE(base::PathExists(latest_symlink_path));
  EXPECT_TRUE(base::PathExists(previous_symlink_path));

  EXPECT_TRUE(base::ReadSymbolicLink(previous_symlink_path, &symlink_target));
  EXPECT_EQ(rotated_path.value(), symlink_target.value());
}

TEST(VmlogWriterTest, WriteCallbackSuccess) {
  base::FilePath tempdir;
  EXPECT_TRUE(base::CreateNewTempDirectory("", &tempdir));

  // Create a VmlogWriter with a zero log_interval to avoid scheduling write
  // callbacks.
  VmlogWriter writer(tempdir, base::TimeDelta());
  writer.WriteCallback();

  EXPECT_TRUE(base::PathExists(writer.vmlog_->live_path_));
  EXPECT_FALSE(base::PathExists(writer.vmlog_->rotated_path_));
}

TEST(VmlogWriterTest, GetOnlineCpus) {
  const char kProcCpuInfo[] =
      R"(processor       : 0
vendor_id       : GenuineIntel
model name      : Intel(R) Core(TM) i5-7Y57 CPU @ 1.20GHz
bugs            : cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass

processor       : 2
vendor_id       : GenuineIntel
model name      : Intel(R) Core(TM) i5-7Y57 CPU @ 1.20GHz
bugs            : cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass)";

  std::istringstream input_stream(kProcCpuInfo);
  auto cpus = GetOnlineCpus(input_stream);

  EXPECT_TRUE(cpus.has_value());
  std::vector<int> expected_cpus = {0, 2};
  EXPECT_EQ(*cpus, expected_cpus);
}

}  // namespace chromeos_metrics
