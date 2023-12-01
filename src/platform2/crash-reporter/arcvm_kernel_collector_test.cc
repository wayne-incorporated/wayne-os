// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/arcvm_kernel_collector.h"

#include <fcntl.h>
#include <unistd.h>
#include <memory>
#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include "crash-reporter/test_util.h"

namespace {

constexpr char kTestCrashDirectory[] = "test-crash-directory";
constexpr char kBasenameWithoutExt[] = "arcvm_kernel.20190101.000000.*.0";
constexpr char kExecName[] = "arcvm-kernel";
constexpr time_t kTimestamp = 1546300800;

constexpr char kDevice[] = "Device";
constexpr char kBoard[] = "Board";
constexpr char kCpuAbi[] = "CPUABI";
constexpr char kFingerprint[] = "Fingerprint";

arc_util::BuildProperty GetBuildProperty() {
  return {.device = kDevice,
          .board = kBoard,
          .cpu_abi = kCpuAbi,
          .fingerprint = kFingerprint};
}

constexpr char kRamoopsSampleContent[] =
    "Panic#1 Part1\n"
    "<6>example@google.com shouled be stripped\n"
    "<0>[ 246.088355] Kernel panic - not syncing: sysrq triggered crash\n"
    "<4>[ 246.089203] CPU: 1 PID: 2536 Comm: sh Not tainted "
    "5.4.73-10450-g5f72588ca054 #1\n"
    "<4>[ 246.090349] Hardware name: ChromiumOS crosvm, BIOS 0\n"
    "<4>[ 246.091050] Call Trace:\n"
    "<4>[ 246.091863] dump_stack+0x88/0xcc\n"
    "<4>[ 246.092693] panic+0x100/0x2f1\n"
    "<4>[ 246.093710] sysrq_handle_crash+0x13/0x13\n"
    "<4>[ 246.094467] __handle_sysrq+0x115/0x12f\n"
    "<4>[ 246.095142] write_sysrq_trigger+0x35/0x49\n"
    "<4>[ 246.095852] proc_reg_write+0x37/0x68\n"
    "<4>[ 246.096549] __vfs_write+0x3d/0x199\n"
    "<4>[ 246.097311] ? selinux_file_permission+0x8f/0x124\n"
    "<4>[ 246.098111] vfs_write+0xea/0x192\n"
    "<4>[ 246.098780] ksys_write+0x68/0xc9\n"
    "<4>[ 246.099484] do_syscall_64+0x4b/0x74\n"
    "<4>[ 246.100151] entry_SYSCALL_64_after_hwframe+0x44/0xa9\n"
    "<4>[ 246.101035] RIP: 0033:0x725b4ecba5b7\n"
    "<4>[ 246.101617] Code: 00 00 00 b8 00 00 00 00 0f 05 48 3d 01 f0 ff ff 72 "
    "09 f7 d8 89 c7 e8 08 fb ff ff c3 0f 1f 80 00 00 00 00 b8 01 00 00 00 0f "
    "05 <48> 3d 01 f0 ff ff 72 09 f7 d8 89 c7 e8 e8 fa ff ff c3 0f 1f 80 00\n"
    "<4>[ 246.103266] RSP: 002b:00007fffc5925ed8 EFLAGS: 00000217 ORIG_RAX: "
    "0000000000000001\n"
    "<4>[ 246.104135] RAX: ffffffffffffffda RBX: 0000000000000002 RCX: "
    "0000725b4ecba5b7\n"
    "<4>[ 246.105117] RDX: 0000000000000002 RSI: 00007259beb72018 RDI: "
    "0000000000000001\n"
    "<4>[ 246.105924] RBP: 00007259beb72018 R08: ffffffffffffffff R09: "
    "000072597eb70368\n"
    "<4>[ 246.106966] R10: 00000000fffffe00 R11: 0000000000000217 R12: "
    "0000589b639779c0\n"
    "<4>[ 246.107815] R13: 00007fffc5925ef0 R14: 00007259eeb75af0 R15: "
    "00007fffc5925f28\n"
    "<0>[ 246.109609] Kernel Offset: 0x26a00000 from 0xffffffff81000000 "
    "(relocation range: 0xffffffff80000000-0xffffffffbfffffff)\n";

constexpr char kKeywordinRamoops[] =
    "Kernel panic - not syncing: sysrq triggered crash";
constexpr char kSensitiveDataInRamoops[] = "example@google.com";

}  // namespace

class TestArcvmKernelCollector : public ArcvmKernelCollector {
 public:
  explicit TestArcvmKernelCollector(const base::FilePath& crash_directory) {
    Initialize(false /* early */);
    set_crash_directory_for_test(crash_directory);
  }
  ~TestArcvmKernelCollector() override = default;

  bool HasMetaData(const std::string& key, const std::string& value) const {
    const std::string metadata =
        base::StringPrintf("%s=%s\n", key.c_str(), value.c_str());
    return extra_metadata_.find(metadata) != std::string::npos;
  }

 private:
  void SetUpDBus() override {}
};

class ArcvmKernelCollectorTest : public ::testing::Test {
 public:
  ~ArcvmKernelCollectorTest() override = default;

  void SetUp() override {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());

    base::FilePath ramoops_path =
        scoped_temp_dir_.GetPath().Append("dmesg-ramoops-0");
    ASSERT_TRUE(test_util::CreateFile(ramoops_path, kRamoopsSampleContent));
    ramoops_stream_ =
        base::ScopedFILE(fopen(ramoops_path.value().c_str(), "r"));
    ASSERT_TRUE(ramoops_stream_);

    test_crash_directory_ =
        scoped_temp_dir_.GetPath().Append(kTestCrashDirectory);
    ASSERT_TRUE(base::CreateDirectory(test_crash_directory_));
    collector_ =
        std::make_unique<TestArcvmKernelCollector>(test_crash_directory_);
  }

 protected:
  base::ScopedTempDir scoped_temp_dir_;
  base::ScopedFILE ramoops_stream_;
  base::FilePath test_crash_directory_;
  std::unique_ptr<TestArcvmKernelCollector> collector_;
};

TEST_F(ArcvmKernelCollectorTest, HandleCrashWithRamoopsStreamAndTimestamp) {
  ASSERT_TRUE(collector_->HandleCrashWithRamoopsStreamAndTimestamp(
      GetBuildProperty(), ramoops_stream_.get(), kTimestamp));

  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, std::string(kBasenameWithoutExt) + ".meta",
      nullptr));

  base::FilePath ramoops_path;
  ASSERT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, std::string(kBasenameWithoutExt) + ".log",
      &ramoops_path));
  std::string ramoops_content;
  EXPECT_TRUE(base::ReadFileToString(ramoops_path, &ramoops_content));
  EXPECT_THAT(ramoops_content, testing::HasSubstr(kKeywordinRamoops));
  EXPECT_THAT(ramoops_content,
              testing::Not(testing::HasSubstr(kSensitiveDataInRamoops)));
}

TEST_F(ArcvmKernelCollectorTest, AddArcMetadata) {
  collector_->AddArcMetadata(GetBuildProperty());
  EXPECT_TRUE(collector_->HasMetaData(arc_util::kProcessField, kExecName));
  EXPECT_TRUE(
      collector_->HasMetaData(arc_util::kProductField, arc_util::kArcProduct));
  EXPECT_TRUE(
      collector_->HasMetaData(arc_util::kArcVersionField, kFingerprint));
  EXPECT_TRUE(collector_->HasMetaData(arc_util::kDeviceField, kDevice));
  EXPECT_TRUE(collector_->HasMetaData(arc_util::kBoardField, kBoard));
  EXPECT_TRUE(collector_->HasMetaData(arc_util::kCpuAbiField, kCpuAbi));
}
