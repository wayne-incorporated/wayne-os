/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <gtest/gtest.h>

#include "libcontainer/cgroup.h"

namespace libcontainer {

namespace {

constexpr char kCgroupName[] = "testcg";
constexpr char kCgroupParentName[] = "testparentcg";

bool CreateFile(const base::FilePath& path) {
  return base::WriteFile(path, "", 0) == 0;
}

bool FileHasString(const base::FilePath& path, const std::string& expected) {
  std::string contents;
  if (!base::ReadFileToString(path, &contents))
    return false;

  return contents.find(expected) != std::string::npos;
}

bool FileHasLine(const base::FilePath& path, const std::string& expected) {
  std::string contents;
  if (!base::ReadFileToString(path, &contents))
    return false;

  for (const auto& line : base::SplitString(
           contents, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY)) {
    if (line == expected)
      return true;
  }
  return false;
}

}  // namespace

TEST(CgroupTest, CgroupNewWithParent) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath cgroup_root = temp_dir.GetPath();

  for (const char* subsystem :
       {"cpu", "cpuacct", "cpuset", "devices", "freezer", "schedtune"}) {
    base::FilePath path = cgroup_root.Append(subsystem);
    EXPECT_EQ(0, mkdir(path.value().c_str(), S_IRWXU | S_IRWXG));
    path = path.Append(kCgroupParentName);
    EXPECT_EQ(0, mkdir(path.value().c_str(), S_IRWXU | S_IRWXG));
  }

  ASSERT_TRUE(base::WriteFile(
      cgroup_root.Append("cpuset").Append(kCgroupParentName).Append("cpus"),
      "0-3", 3));
  ASSERT_TRUE(base::WriteFile(
      cgroup_root.Append("cpuset").Append(kCgroupParentName).Append("mems"),
      "0", 1));

  std::unique_ptr<libcontainer::Cgroup> ccg = libcontainer::Cgroup::Create(
      kCgroupName, cgroup_root, base::FilePath(kCgroupParentName), getuid(),
      getgid());
  ASSERT_NE(nullptr, ccg.get());

  EXPECT_TRUE(base::DirectoryExists(
      cgroup_root.Append("cpu").Append(kCgroupParentName).Append(kCgroupName)));
  EXPECT_TRUE(base::DirectoryExists(cgroup_root.Append("cpuacct")
                                        .Append(kCgroupParentName)
                                        .Append(kCgroupName)));
  EXPECT_TRUE(base::DirectoryExists(cgroup_root.Append("cpuset")
                                        .Append(kCgroupParentName)
                                        .Append(kCgroupName)));
  EXPECT_TRUE(base::DirectoryExists(cgroup_root.Append("devices")
                                        .Append(kCgroupParentName)
                                        .Append(kCgroupName)));
  EXPECT_TRUE(base::DirectoryExists(cgroup_root.Append("freezer")
                                        .Append(kCgroupParentName)
                                        .Append(kCgroupName)));
  EXPECT_TRUE(base::DirectoryExists(cgroup_root.Append("schedtune")
                                        .Append(kCgroupParentName)
                                        .Append(kCgroupName)));

  EXPECT_TRUE(temp_dir.Delete());
}

class BasicCgroupManipulationTest : public ::testing::Test {
 public:
  BasicCgroupManipulationTest() = default;
  ~BasicCgroupManipulationTest() override = default;

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

    base::FilePath cgroup_root;
    ASSERT_TRUE(base::CreateTemporaryDirInDir(temp_dir_.GetPath(), "cgtest",
                                              &cgroup_root));

    for (const char* subsystem :
         {"cpu", "cpuacct", "cpuset", "devices", "freezer", "schedtune"}) {
      base::FilePath path = cgroup_root.Append(subsystem);
      ASSERT_EQ(0, mkdir(path.value().c_str(), S_IRWXU | S_IRWXG));
    }

    ASSERT_TRUE(base::WriteFile(cgroup_root.Append("cpuset/cpus"), "0-3", 3));
    ASSERT_TRUE(base::WriteFile(cgroup_root.Append("cpuset/mems"), "0", 1));

    ccg_ = libcontainer::Cgroup::Create(kCgroupName, cgroup_root,
                                        base::FilePath(), 0, 0);
    ASSERT_NE(nullptr, ccg_.get());

    cpu_cg_ = cgroup_root.Append("cpu").Append(kCgroupName);
    cpuacct_cg_ = cgroup_root.Append("cpuacct").Append(kCgroupName);
    cpuset_cg_ = cgroup_root.Append("cpuset").Append(kCgroupName);
    devices_cg_ = cgroup_root.Append("devices").Append(kCgroupName);
    freezer_cg_ = cgroup_root.Append("freezer").Append(kCgroupName);
    schedtune_cg_ = cgroup_root.Append("schedtune").Append(kCgroupName);

    ASSERT_TRUE(base::DirectoryExists(cpu_cg_));
    ASSERT_TRUE(base::DirectoryExists(cpuacct_cg_));
    ASSERT_TRUE(base::DirectoryExists(cpuset_cg_));
    ASSERT_TRUE(base::DirectoryExists(devices_cg_));
    ASSERT_TRUE(base::DirectoryExists(freezer_cg_));
    ASSERT_TRUE(base::DirectoryExists(schedtune_cg_));

    ASSERT_TRUE(CreateFile(cpu_cg_.Append("tasks")));
    ASSERT_TRUE(CreateFile(cpu_cg_.Append("cpu.shares")));
    ASSERT_TRUE(CreateFile(cpu_cg_.Append("cpu.cfs_quota_us")));
    ASSERT_TRUE(CreateFile(cpu_cg_.Append("cpu.cfs_period_us")));
    ASSERT_TRUE(CreateFile(cpu_cg_.Append("cpu.rt_runtime_us")));
    ASSERT_TRUE(CreateFile(cpu_cg_.Append("cpu.rt_period_us")));
    ASSERT_TRUE(CreateFile(cpuacct_cg_.Append("tasks")));
    ASSERT_TRUE(CreateFile(cpuset_cg_.Append("tasks")));
    ASSERT_TRUE(CreateFile(devices_cg_.Append("tasks")));
    ASSERT_TRUE(CreateFile(devices_cg_.Append("devices.allow")));
    ASSERT_TRUE(CreateFile(devices_cg_.Append("devices.deny")));
    ASSERT_TRUE(CreateFile(freezer_cg_.Append("tasks")));
    ASSERT_TRUE(CreateFile(freezer_cg_.Append("freezer.state")));
    ASSERT_TRUE(CreateFile(schedtune_cg_.Append("tasks")));
  }

  void TearDown() override {
    ccg_.reset();
    ASSERT_TRUE(temp_dir_.Delete());
  }

 protected:
  std::unique_ptr<libcontainer::Cgroup> ccg_;

  base::FilePath cpu_cg_;
  base::FilePath cpuacct_cg_;
  base::FilePath cpuset_cg_;
  base::FilePath devices_cg_;
  base::FilePath freezer_cg_;
  base::FilePath schedtune_cg_;

  base::ScopedTempDir temp_dir_;
};

TEST_F(BasicCgroupManipulationTest, freeze) {
  EXPECT_TRUE(ccg_->Freeze());
  EXPECT_TRUE(FileHasString(freezer_cg_.Append("freezer.state"), "FROZEN"));
}

TEST_F(BasicCgroupManipulationTest, thaw) {
  EXPECT_TRUE(ccg_->Thaw());
  EXPECT_TRUE(FileHasString(freezer_cg_.Append("freezer.state"), "THAWED"));
}

TEST_F(BasicCgroupManipulationTest, default_all_devs_disallow) {
  ASSERT_TRUE(ccg_->DenyAllDevices());
  EXPECT_TRUE(FileHasLine(devices_cg_.Append("devices.deny"), "a"));
}

TEST_F(BasicCgroupManipulationTest, add_device_invalid_type) {
  EXPECT_FALSE(ccg_->AddDevice(1, 14, 3, 1, 1, 0, 'x'));
}

TEST_F(BasicCgroupManipulationTest, add_device_no_perms) {
  EXPECT_FALSE(ccg_->AddDevice(1, 14, 3, 0, 0, 0, 'c'));
}

TEST_F(BasicCgroupManipulationTest, add_device_rw) {
  EXPECT_TRUE(ccg_->AddDevice(1, 14, 3, 1, 1, 0, 'c'));
  EXPECT_TRUE(FileHasLine(devices_cg_.Append("devices.allow"), "c 14:3 rw"));
}

TEST_F(BasicCgroupManipulationTest, add_device_rwm) {
  EXPECT_TRUE(ccg_->AddDevice(1, 14, 3, 1, 1, 1, 'c'));
  EXPECT_TRUE(FileHasLine(devices_cg_.Append("devices.allow"), "c 14:3 rwm"));
}

TEST_F(BasicCgroupManipulationTest, add_device_ro) {
  EXPECT_TRUE(ccg_->AddDevice(1, 14, 3, 1, 0, 0, 'c'));
  EXPECT_TRUE(FileHasLine(devices_cg_.Append("devices.allow"), "c 14:3 r"));
}

TEST_F(BasicCgroupManipulationTest, add_device_wo) {
  EXPECT_TRUE(ccg_->AddDevice(1, 14, 3, 0, 1, 0, 'c'));
  EXPECT_TRUE(FileHasLine(devices_cg_.Append("devices.allow"), "c 14:3 w"));
}

TEST_F(BasicCgroupManipulationTest, add_device_major_wide) {
  EXPECT_TRUE(ccg_->AddDevice(1, 14, -1, 0, 1, 0, 'c'));
  EXPECT_TRUE(FileHasLine(devices_cg_.Append("devices.allow"), "c 14:* w"));
}

TEST_F(BasicCgroupManipulationTest, add_device_major_minor_wildcard) {
  EXPECT_TRUE(ccg_->AddDevice(1, -1, -1, 0, 1, 0, 'c'));
  EXPECT_TRUE(FileHasLine(devices_cg_.Append("devices.allow"), "c *:* w"));
}

TEST_F(BasicCgroupManipulationTest, add_device_deny_all) {
  EXPECT_TRUE(ccg_->AddDevice(0, -1, -1, 1, 1, 1, 'a'));
  EXPECT_TRUE(FileHasLine(devices_cg_.Append("devices.deny"), "a *:* rwm"));
}

TEST_F(BasicCgroupManipulationTest, add_device_block) {
  EXPECT_TRUE(ccg_->AddDevice(1, 14, 3, 1, 1, 0, 'b'));
  EXPECT_TRUE(FileHasLine(devices_cg_.Append("devices.allow"), "b 14:3 rw"));
}

TEST_F(BasicCgroupManipulationTest, set_cpu_shares) {
  EXPECT_TRUE(ccg_->SetCpuShares(500));
  EXPECT_TRUE(FileHasString(cpu_cg_.Append("cpu.shares"), "500"));
}

TEST_F(BasicCgroupManipulationTest, set_cpu_quota) {
  EXPECT_TRUE(ccg_->SetCpuQuota(200000));
  EXPECT_TRUE(FileHasString(cpu_cg_.Append("cpu.cfs_quota_us"), "200000"));
}

TEST_F(BasicCgroupManipulationTest, set_cpu_period) {
  EXPECT_TRUE(ccg_->SetCpuPeriod(800000));
  EXPECT_TRUE(FileHasString(cpu_cg_.Append("cpu.cfs_period_us"), "800000"));
}

TEST_F(BasicCgroupManipulationTest, set_cpu_rt_runtime) {
  EXPECT_TRUE(ccg_->SetCpuRtRuntime(100000));
  EXPECT_TRUE(FileHasString(cpu_cg_.Append("cpu.rt_runtime_us"), "100000"));
}

TEST_F(BasicCgroupManipulationTest, set_cpu_rt_period) {
  EXPECT_TRUE(ccg_->SetCpuRtPeriod(500000));
  EXPECT_TRUE(FileHasString(cpu_cg_.Append("cpu.rt_period_us"), "500000"));
}

TEST_F(BasicCgroupManipulationTest, OpenCgroupFileRefusesToWriteToSymlink) {
  base::FilePath cpu_rt_period_us_path = cpu_cg_.Append("cpu.rt_period_us");
  base::FilePath target_path = cpu_cg_.Append("symlink_target");
  ASSERT_TRUE(base::DeleteFile(cpu_rt_period_us_path));
  ASSERT_TRUE(base::CreateSymbolicLink(target_path, cpu_rt_period_us_path));

  // This should fail since we are trying to write to a symlink.
  EXPECT_FALSE(ccg_->SetCpuRtPeriod(500000));
}

TEST_F(BasicCgroupManipulationTest, OpenCgroupFileRefusesToWriteToNonOpenFIFO) {
  base::FilePath cpu_rt_period_us_path = cpu_cg_.Append("cpu.rt_period_us");
  ASSERT_TRUE(base::DeleteFile(cpu_rt_period_us_path));
  ASSERT_NE(mkfifo(cpu_rt_period_us_path.value().c_str(), 0664), -1);

  // This should fail since we are trying to write to a FIFO.
  EXPECT_FALSE(ccg_->SetCpuRtPeriod(500000));
}

TEST_F(BasicCgroupManipulationTest, OpenCgroupFileRefusesToWriteToOpenFIFO) {
  base::FilePath cpu_rt_period_us_path = cpu_cg_.Append("cpu.rt_period_us");
  ASSERT_TRUE(base::DeleteFile(cpu_rt_period_us_path));
  ASSERT_NE(mkfifo(cpu_rt_period_us_path.value().c_str(), 0664), -1);
  base::ScopedFD fd(
      open(cpu_rt_period_us_path.value().c_str(), O_RDONLY | O_NONBLOCK));
  ASSERT_TRUE(fd.is_valid());

  // This should fail since we are trying to write to a FIFO.
  EXPECT_FALSE(ccg_->SetCpuRtPeriod(500000));
}

}  // namespace libcontainer
