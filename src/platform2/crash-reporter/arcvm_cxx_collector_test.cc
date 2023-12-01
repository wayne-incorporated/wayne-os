// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/arcvm_cxx_collector.h"

#include <fcntl.h>
#include <memory>
#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include "crash-reporter/arc_util.h"
#include "crash-reporter/test_util.h"

namespace {

constexpr char kDevice[] = "Device";
constexpr char kBoard[] = "Board";
constexpr char kCpuAbi[] = "CPUABI";
constexpr char kFingerprint[] = "Fingerprint";

// 1546300800 is unixtime of 2019-01-01 00:00:00
constexpr time_t kTime = 1546300800;
constexpr pid_t kPid = 1234;
constexpr char kExecName[] = "execname";

constexpr base::TimeDelta kUptimeValue =
    base::Milliseconds(123456789);  // 1d 10h 17min 36s
constexpr char kUptimeFormatted[] = "1d 10h 17min 36s";

constexpr char kTestCrashDirectory[] = "test-crash-directory";
constexpr char kBasenameWithoutExt[] = "execname.20190101.000000.*.1234";

constexpr char kMinidumpSampleContent[] = "*minidump*";

arc_util::BuildProperty GetBuildProperty() {
  return {.device = kDevice,
          .board = kBoard,
          .cpu_abi = kCpuAbi,
          .fingerprint = kFingerprint};
}
ArcvmCxxCollector::CrashInfo GetCrashInfo() {
  return {.time = kTime, .pid = kPid, .exec_name = kExecName};
}

}  // namespace

class TestArcvmCxxCollector : public ArcvmCxxCollector {
 public:
  explicit TestArcvmCxxCollector(const base::FilePath& crash_directory) {
    Initialize(false /* early */);
    set_crash_directory_for_test(crash_directory);
  }
  ~TestArcvmCxxCollector() override = default;

  bool HasMetaData(const std::string& key, const std::string& value) const {
    const std::string metadata =
        base::StringPrintf("%s=%s\n", key.c_str(), value.c_str());
    return extra_metadata_.find(metadata) != std::string::npos;
  }

 private:
  void SetUpDBus() override {}
};

class ArcvmCxxCollectorTest : public ::testing::Test {
 public:
  ~ArcvmCxxCollectorTest() override = default;

  void SetUp() override {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());

    base::FilePath minidump_path =
        scoped_temp_dir_.GetPath().Append("minidump.dmp");
    ASSERT_TRUE(test_util::CreateFile(minidump_path, kMinidumpSampleContent));
    minidump_fd_ = base::ScopedFD(
        HANDLE_EINTR(open(minidump_path.value().c_str(), O_RDONLY)));
    ASSERT_NE(minidump_fd_, -1);

    test_crash_directory_ =
        scoped_temp_dir_.GetPath().Append(kTestCrashDirectory);
    ASSERT_TRUE(base::CreateDirectory(test_crash_directory_));
    collector_ = std::make_unique<TestArcvmCxxCollector>(test_crash_directory_);
  }

 protected:
  std::unique_ptr<TestArcvmCxxCollector> collector_;
  base::ScopedTempDir scoped_temp_dir_;
  base::FilePath test_crash_directory_;
  base::ScopedFD minidump_fd_;
};

TEST_F(ArcvmCxxCollectorTest, HandleCrashWithMinidumpFD) {
  ASSERT_TRUE(collector_->HandleCrashWithMinidumpFD(
      GetBuildProperty(), GetCrashInfo(), kUptimeValue,
      std::move(minidump_fd_)));

  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, std::string(kBasenameWithoutExt) + ".meta",
      nullptr));

  base::FilePath minidump_path;
  ASSERT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, std::string(kBasenameWithoutExt) + ".dmp",
      &minidump_path));
  std::string minidump_content;
  EXPECT_TRUE(base::ReadFileToString(minidump_path, &minidump_content));
  EXPECT_EQ(minidump_content, kMinidumpSampleContent);
}

TEST_F(ArcvmCxxCollectorTest, AddArcMetadata) {
  collector_->AddArcMetadata(GetBuildProperty(), GetCrashInfo(), kUptimeValue);
  EXPECT_TRUE(collector_->HasMetaData(arc_util::kProcessField, kExecName));
  EXPECT_TRUE(
      collector_->HasMetaData(arc_util::kArcVersionField, kFingerprint));
  EXPECT_TRUE(collector_->HasMetaData(arc_util::kDeviceField, kDevice));
  EXPECT_TRUE(collector_->HasMetaData(arc_util::kBoardField, kBoard));
  EXPECT_TRUE(collector_->HasMetaData(arc_util::kCpuAbiField, kCpuAbi));
  EXPECT_TRUE(
      collector_->HasMetaData(arc_util::kUptimeField, kUptimeFormatted));
}
