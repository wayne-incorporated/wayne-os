// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <time.h>

#include <deque>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/values.h>
#include <brillo/blkdev_utils/mock_lvm.h>
#include <brillo/blkdev_utils/lvm.h>
#include <gtest/gtest.h>

#include "init/crossystem.h"
#include "init/crossystem_fake.h"
#include "init/startup/chromeos_startup.h"
#include "init/startup/fake_platform_impl.h"
#include "init/startup/mock_platform_impl.h"
#include "init/startup/platform_impl.h"
#include "init/startup/standard_mount_helper.h"

using testing::_;
using testing::ByMove;
using testing::Return;
using testing::StrictMock;

namespace {

const char kImageVarsContent[] =
    R"({"load_base_vars": {"FORMAT_STATE": "base", "PLATFORM_FORMAT_STATE": )"
    R"("ext4", "PLATFORM_OPTIONS_STATE": "", "PARTITION_NUM_STATE": 1},)"
    R"("load_partition_vars": {"FORMAT_STATE": "partition", )"
    R"("PLATFORM_FORMAT_STATE": "ext4", "PLATFORM_OPTIONS_STATE": "", )"
    R"("PARTITION_NUM_STATE": 1}})";

constexpr char kDumpe2fsStr[] =
    "dumpe2fs\n%s(group "
    "android-reserved-disk)\nFilesystem features:      %s\n";

constexpr char kReservedBlocksGID[] = "Reserved blocks gid:      20119";
constexpr char kStatefulPartition[] = "mnt/stateful_partition";

constexpr char kHiberResumeInitLog[] = "run/hibernate/hiber-resume-init.log";

// Helper function to create directory and write to file.
bool CreateDirAndWriteFile(const base::FilePath& path,
                           const std::string& contents) {
  return base::CreateDirectory(path.DirName()) &&
         base::WriteFile(path, contents.c_str(), contents.length()) ==
             contents.length();
}

}  // namespace

TEST(GetImageVars, BaseVars) {
  base::ScopedTempDir temp_dir_;
  ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  base::FilePath json_file = temp_dir_.GetPath().Append("vars.json");
  ASSERT_TRUE(WriteFile(json_file, kImageVarsContent));
  base::Value vars;
  ASSERT_TRUE(
      startup::StatefulMount::GetImageVars(json_file, "load_base_vars", &vars));
  LOG(INFO) << "vars is: " << vars;
  EXPECT_TRUE(vars.is_dict());
  const std::string* format = vars.GetDict().FindString("FORMAT_STATE");
  EXPECT_NE(format, nullptr);
  EXPECT_EQ(*format, "base");
}

TEST(GetImageVars, PartitionVars) {
  base::ScopedTempDir temp_dir_;
  ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  base::FilePath json_file = temp_dir_.GetPath().Append("vars.json");
  ASSERT_TRUE(WriteFile(json_file, kImageVarsContent));
  base::Value vars;
  ASSERT_TRUE(startup::StatefulMount::GetImageVars(
      json_file, "load_partition_vars", &vars));
  LOG(INFO) << "vars is: " << vars;
  EXPECT_TRUE(vars.is_dict());
  const std::string* format = vars.GetDict().FindString("FORMAT_STATE");
  LOG(INFO) << "FORMAT_STATE is: " << *format;
  EXPECT_NE(format, nullptr);
  EXPECT_EQ(*format, "partition");
}

class Ext4FeaturesTest : public ::testing::Test {
 protected:
  Ext4FeaturesTest() {}

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    base_dir = temp_dir_.GetPath();
    platform_ = std::make_unique<startup::FakePlatform>();
    mount_helper_ = std::make_unique<startup::StandardMountHelper>(
        std::make_unique<startup::FakePlatform>(), flags_, base_dir, base_dir,
        true);
  }

  startup::Flags flags_;
  std::unique_ptr<startup::StatefulMount> stateful_mount_;
  base::ScopedTempDir temp_dir_;
  base::FilePath base_dir;
  std::unique_ptr<startup::FakePlatform> platform_;
  std::unique_ptr<startup::StandardMountHelper> mount_helper_;
};

TEST_F(Ext4FeaturesTest, Encrypt) {
  std::string state_dump =
      base::StringPrintf(kDumpe2fsStr, kReservedBlocksGID, "verity");
  startup::Flags flags;
  flags.direncryption = true;
  base::FilePath encrypt_file =
      base_dir.Append("sys/fs/ext4/features/encryption");
  ASSERT_TRUE(CreateDirAndWriteFile(encrypt_file, "1"));

  struct stat st;
  platform_->SetStatResultForPath(encrypt_file, st);

  stateful_mount_ = std::make_unique<startup::StatefulMount>(
      flags, base_dir, base_dir, platform_.get(),
      std::unique_ptr<brillo::MockLogicalVolumeManager>(), mount_helper_.get());
  std::vector<std::string> features =
      stateful_mount_->GenerateExt4Features(state_dump);
  std::string features_str = base::JoinString(features, " ");
  EXPECT_EQ(features_str, "-O encrypt");
}

TEST_F(Ext4FeaturesTest, Verity) {
  std::string state_dump =
      base::StringPrintf(kDumpe2fsStr, kReservedBlocksGID, "encrypt");
  startup::Flags flags;
  flags.fsverity = true;
  base::FilePath verity_file = base_dir.Append("sys/fs/ext4/features/verity");
  ASSERT_TRUE(CreateDirAndWriteFile(verity_file, "1"));

  struct stat st;
  platform_->SetStatResultForPath(verity_file, st);

  stateful_mount_ = std::make_unique<startup::StatefulMount>(
      flags, base_dir, base_dir, platform_.get(),
      std::unique_ptr<brillo::MockLogicalVolumeManager>(), mount_helper_.get());
  std::vector<std::string> features =
      stateful_mount_->GenerateExt4Features(state_dump);
  std::string features_str = base::JoinString(features, " ");
  EXPECT_EQ(features_str, "-O verity");
}

TEST_F(Ext4FeaturesTest, ReservedBlocksGID) {
  std::string state_dump =
      base::StringPrintf(kDumpe2fsStr, "", "encrypt verity");
  startup::Flags flags;

  stateful_mount_ = std::make_unique<startup::StatefulMount>(
      flags, base_dir, base_dir, platform_.get(),
      std::unique_ptr<brillo::MockLogicalVolumeManager>(), mount_helper_.get());
  std::vector<std::string> features =
      stateful_mount_->GenerateExt4Features(state_dump);
  std::string features_str = base::JoinString(features, " ");
  EXPECT_EQ(features_str, "-g 20119");
}

TEST_F(Ext4FeaturesTest, EnableQuotaWithPrjQuota) {
  std::string state_dump =
      base::StringPrintf(kDumpe2fsStr, kReservedBlocksGID, "encrypt verity");
  startup::Flags flags;
  flags.prjquota = true;
  base::FilePath quota_file = base_dir.Append("proc/sys/fs/quota");
  ASSERT_TRUE(base::CreateDirectory(quota_file));

  struct stat st;
  st.st_mode = S_IFDIR;
  platform_->SetStatResultForPath(quota_file, st);

  stateful_mount_ = std::make_unique<startup::StatefulMount>(
      flags, base_dir, base_dir, platform_.get(),
      std::unique_ptr<brillo::MockLogicalVolumeManager>(), mount_helper_.get());
  std::vector<std::string> features =
      stateful_mount_->GenerateExt4Features(state_dump);
  std::string features_str = base::JoinString(features, " ");
  EXPECT_EQ(features_str, "-Qusrquota,grpquota -Qprjquota -O quota");
}

TEST_F(Ext4FeaturesTest, EnableQuotaNoPrjQuota) {
  std::string state_dump = base::StringPrintf(kDumpe2fsStr, kReservedBlocksGID,
                                              "encrypt verity project");
  startup::Flags flags;
  flags.prjquota = false;
  base::FilePath quota_file = base_dir.Append("proc/sys/fs/quota");
  ASSERT_TRUE(base::CreateDirectory(quota_file));

  struct stat st;
  st.st_mode = S_IFDIR;
  platform_->SetStatResultForPath(quota_file, st);

  stateful_mount_ = std::make_unique<startup::StatefulMount>(
      flags, base_dir, base_dir, platform_.get(),
      std::unique_ptr<brillo::MockLogicalVolumeManager>(), mount_helper_.get());
  std::vector<std::string> features =
      stateful_mount_->GenerateExt4Features(state_dump);
  std::string features_str = base::JoinString(features, " ");
  EXPECT_EQ(features_str, "-Qusrquota,grpquota -Q^prjquota -O quota");
}

TEST_F(Ext4FeaturesTest, DisableQuota) {
  std::string state_dump = base::StringPrintf(kDumpe2fsStr, kReservedBlocksGID,
                                              "encrypt verityquota");
  startup::Flags flags;

  stateful_mount_ = std::make_unique<startup::StatefulMount>(
      flags, base_dir, base_dir, platform_.get(),
      std::unique_ptr<brillo::MockLogicalVolumeManager>(), mount_helper_.get());
  std::vector<std::string> features =
      stateful_mount_->GenerateExt4Features(state_dump);
  std::string features_str = base::JoinString(features, " ");
  EXPECT_EQ(features_str, "-Q^usrquota,^grpquota,^prjquota -O ^quota");
}

TEST_F(Ext4FeaturesTest, MissingFeatures) {
  std::string state_dump("");
  startup::Flags flags;

  stateful_mount_ = std::make_unique<startup::StatefulMount>(
      flags, base_dir, base_dir, platform_.get(),
      std::unique_ptr<brillo::MockLogicalVolumeManager>(), mount_helper_.get());
  std::vector<std::string> features =
      stateful_mount_->GenerateExt4Features(state_dump);
  std::string features_str = base::JoinString(features, " ");
  EXPECT_EQ(features_str, "-g 20119");
}

class HibernateResumeBootTest : public ::testing::Test {
 protected:
  HibernateResumeBootTest() {}

  void SetUp() override {
    cros_system_ = std::make_unique<CrosSystemFake>();
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    base_dir_ = temp_dir_.GetPath();
    mock_platform_ = std::make_unique<StrictMock<startup::MockPlatform>>();
    mount_helper_ = std::make_unique<startup::StandardMountHelper>(
        std::make_unique<startup::FakePlatform>(), flags_, base_dir_, base_dir_,
        true);
    stateful_mount_ = std::make_unique<startup::StatefulMount>(
        flags_, base_dir_, base_dir_, mock_platform_.get(),
        std::unique_ptr<brillo::MockLogicalVolumeManager>(),
        mount_helper_.get());
    state_dev_ = base::FilePath("test");
    hiber_init_log_ = base_dir_.Append(kHiberResumeInitLog);
  }

  std::unique_ptr<CrosSystemFake> cros_system_;
  startup::Flags flags_;
  std::unique_ptr<startup::MockPlatform> mock_platform_;
  std::unique_ptr<startup::StandardMountHelper> mount_helper_;
  std::unique_ptr<startup::StatefulMount> stateful_mount_;
  base::ScopedTempDir temp_dir_;
  base::FilePath base_dir_;
  base::FilePath state_dev_;
  base::FilePath hiber_init_log_;
};

TEST_F(HibernateResumeBootTest, NoHibermanFile) {
  stateful_mount_->SetStateDevForTest(state_dev_);
  EXPECT_FALSE(stateful_mount_->HibernateResumeBoot());
}

TEST_F(HibernateResumeBootTest, HibermanFail) {
  stateful_mount_->SetStateDevForTest(state_dev_);
  base::FilePath hiberman = base_dir_.Append("usr/sbin/hiberman");
  ASSERT_TRUE(CreateDirAndWriteFile(hiberman, "1"));

  EXPECT_CALL(*mock_platform_, RunHiberman(hiber_init_log_))
      .WillOnce(Return(false));

  EXPECT_FALSE(stateful_mount_->HibernateResumeBoot());
}

TEST_F(HibernateResumeBootTest, HibermanSuccess) {
  stateful_mount_->SetStateDevForTest(state_dev_);
  base::FilePath hiberman = base_dir_.Append("usr/sbin/hiberman");
  ASSERT_TRUE(CreateDirAndWriteFile(hiberman, "1"));

  EXPECT_CALL(*mock_platform_, RunHiberman(hiber_init_log_))
      .WillOnce(Return(true));

  EXPECT_TRUE(stateful_mount_->HibernateResumeBoot());
}

class DevUpdateStatefulTest : public ::testing::Test {
 protected:
  DevUpdateStatefulTest() {}

  void SetUp() override {
    cros_system_ = std::make_unique<CrosSystemFake>();
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    base_dir = temp_dir_.GetPath();
    stateful = base_dir.Append(kStatefulPartition);
    platform_ = std::make_unique<startup::FakePlatform>();
    stateful_update_file = stateful.Append(".update_available");
    clobber_log_ = base_dir.Append("clobber_log");
    var_new = stateful.Append("var_new");
    var_target = stateful.Append("var_overlay");
    developer_target = stateful.Append("dev_image");
    developer_new = stateful.Append("dev_image_new");
    preserve_dir = stateful.Append("unencrypted/preserve");
    mount_helper_ = std::make_unique<startup::StandardMountHelper>(
        std::make_unique<startup::FakePlatform>(), flags_, base_dir, base_dir,
        true);
    stateful_mount_ = std::make_unique<startup::StatefulMount>(
        flags_, base_dir, stateful, platform_.get(),
        std::unique_ptr<brillo::MockLogicalVolumeManager>(),
        mount_helper_.get());
  }

  std::unique_ptr<CrosSystemFake> cros_system_;
  base::ScopedTempDir temp_dir_;
  base::FilePath base_dir;
  base::FilePath stateful;
  std::unique_ptr<startup::FakePlatform> platform_;
  startup::Flags flags_;
  std::unique_ptr<startup::StandardMountHelper> mount_helper_;
  std::unique_ptr<startup::StatefulMount> stateful_mount_;
  base::FilePath clobber_log_;
  base::FilePath stateful_update_file;
  base::FilePath var_new;
  base::FilePath var_target;
  base::FilePath developer_target;
  base::FilePath developer_new;
  base::FilePath preserve_dir;
};

TEST_F(DevUpdateStatefulTest, NoUpdateAvailable) {
  EXPECT_EQ(stateful_mount_->DevUpdateStatefulPartition(""), true);
}

TEST_F(DevUpdateStatefulTest, NewDevAndVarNoClobber) {
  ASSERT_TRUE(CreateDirectory(developer_new));
  ASSERT_TRUE(CreateDirectory(var_new));
  struct stat st;
  st.st_mode = S_IFDIR;
  platform_->SetStatResultForPath(developer_new, st);
  platform_->SetStatResultForPath(var_new, st);
  platform_->SetClobberLogFile(clobber_log_);

  ASSERT_TRUE(CreateDirAndWriteFile(stateful_update_file, "1"));
  st.st_mode = S_IFREG;
  platform_->SetStatResultForPath(stateful_update_file, st);

  LOG(INFO) << "var new test: " << var_new.value();
  LOG(INFO) << "developer_new test: " << developer_new.value();

  ASSERT_TRUE(CreateDirAndWriteFile(developer_new.Append("dev_new_file"), "1"));
  ASSERT_TRUE(CreateDirAndWriteFile(var_new.Append("var_new_file"), "1"));
  ASSERT_TRUE(
      CreateDirAndWriteFile(developer_target.Append("dev_target_file"), "1"));
  ASSERT_TRUE(CreateDirAndWriteFile(var_target.Append("var_target_file"), "1"));

  EXPECT_EQ(stateful_mount_->DevUpdateStatefulPartition(""), true);

  EXPECT_EQ(PathExists(developer_new.Append("dev_new_file")), false);
  EXPECT_EQ(PathExists(var_new.Append("var_new_file")), false);
  EXPECT_EQ(PathExists(developer_target.Append("dev_target_file")), false);
  EXPECT_EQ(PathExists(var_target.Append("var_target_file")), false);

  EXPECT_EQ(PathExists(stateful_update_file), false);
  EXPECT_EQ(PathExists(var_target.Append("var_new_file")), true);
  EXPECT_EQ(PathExists(developer_target.Append("dev_new_file")), true);

  std::string message = "'Updating from " + developer_new.value() + " && " +
                        var_new.value() + ".'";
  std::string res;
  ASSERT_TRUE(base::ReadFileToString(clobber_log_, &res));
  EXPECT_EQ(res, message);
}

TEST_F(DevUpdateStatefulTest, NoNewDevAndVarWithClobber) {
  platform_->SetClobberLogFile(clobber_log_);

  ASSERT_TRUE(CreateDirAndWriteFile(stateful_update_file, "clobber"));
  base::FilePath labmachine = stateful.Append(".labmachine");
  base::FilePath test_dir = stateful.Append("test");
  base::FilePath test = test_dir.Append("test");
  base::FilePath preserve_test = preserve_dir.Append("test");
  base::FilePath empty = stateful.Append("empty");

  struct stat st;
  st.st_mode = S_IFREG;
  platform_->SetStatResultForPath(stateful_update_file, st);
  platform_->SetStatResultForPath(labmachine, st);
  platform_->SetStatResultForPath(test, st);

  st.st_mode = S_IFDIR;
  platform_->SetStatResultForPath(test_dir, st);
  platform_->SetStatResultForPath(empty, st);
  platform_->SetStatResultForPath(preserve_dir, st);

  ASSERT_TRUE(base::CreateDirectory(empty));
  ASSERT_TRUE(base::CreateDirectory(test_dir));
  ASSERT_TRUE(
      CreateDirAndWriteFile(developer_target.Append("dev_target_file"), "1"));
  ASSERT_TRUE(CreateDirAndWriteFile(var_target.Append("var_target_file"), "1"));
  ASSERT_TRUE(CreateDirAndWriteFile(labmachine, "1"));
  ASSERT_TRUE(CreateDirAndWriteFile(test, "1"));
  ASSERT_TRUE(CreateDirAndWriteFile(preserve_test, "1"));

  EXPECT_EQ(stateful_mount_->DevUpdateStatefulPartition(""), true);
  EXPECT_EQ(PathExists(developer_target.Append("dev_target_file")), true);
  EXPECT_EQ(PathExists(var_target.Append("var_target_file")), true);
  EXPECT_EQ(PathExists(labmachine), true);
  EXPECT_EQ(PathExists(test_dir), false);
  EXPECT_EQ(PathExists(preserve_test), true);
  EXPECT_EQ(PathExists(empty), false);

  std::string message = "'Stateful update did not find " +
                        developer_new.value() + " & " + var_new.value() +
                        ".'\n'Keeping old development tools.'";
  std::string res;
  ASSERT_TRUE(base::ReadFileToString(clobber_log_, &res));
  EXPECT_EQ(res, message);
}

class DevGatherLogsTest : public ::testing::Test {
 protected:
  DevGatherLogsTest() {}

  void SetUp() override {
    cros_system_ = std::make_unique<CrosSystemFake>();
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    base_dir = temp_dir_.GetPath();
    stateful = base_dir.Append(kStatefulPartition);
    platform_ = std::make_unique<startup::FakePlatform>();
    mount_helper_ = std::make_unique<startup::StandardMountHelper>(
        std::make_unique<startup::FakePlatform>(), flags_, base_dir, base_dir,
        true);
    stateful_mount_ = std::make_unique<startup::StatefulMount>(
        flags_, base_dir, stateful, platform_.get(),
        std::unique_ptr<brillo::MockLogicalVolumeManager>(),
        mount_helper_.get());
    lab_preserve_logs_ = stateful.Append(".gatherme");
    prior_log_dir_ = stateful.Append("unencrypted/prior_logs");
    var_dir_ = base_dir.Append("var");
    home_chronos_ = base_dir.Append("home/chronos");
    ASSERT_TRUE(base::CreateDirectory(prior_log_dir_));
    ASSERT_TRUE(base::CreateDirectory(var_dir_));
    ASSERT_TRUE(base::CreateDirectory(home_chronos_));
  }

  std::unique_ptr<CrosSystemFake> cros_system_;
  base::ScopedTempDir temp_dir_;
  base::FilePath base_dir;
  base::FilePath stateful;
  base::FilePath lab_preserve_logs_;
  base::FilePath prior_log_dir_;
  base::FilePath var_dir_;
  base::FilePath home_chronos_;
  std::unique_ptr<startup::FakePlatform> platform_;
  startup::Flags flags_;
  std::unique_ptr<startup::StandardMountHelper> mount_helper_;
  std::unique_ptr<startup::StatefulMount> stateful_mount_;
};

TEST_F(DevGatherLogsTest, NoPreserveLogs) {
  ASSERT_TRUE(CreateDirAndWriteFile(lab_preserve_logs_, "#"));
  struct stat st;
  st.st_mode = S_IFDIR;
  platform_->SetStatResultForPath(lab_preserve_logs_, st);

  stateful_mount_->DevGatherLogs(base_dir);
}

TEST_F(DevGatherLogsTest, PreserveLogs) {
  base::FilePath test = base_dir.Append("test");
  base::FilePath test1 = test.Append("test1");
  base::FilePath test2 = test.Append("test2");
  base::FilePath standalone = base_dir.Append("parent/standalone");
  base::FilePath var_logs = base_dir.Append("var/logs");
  base::FilePath log1 = var_logs.Append("log1");
  base::FilePath home_chronos = base_dir.Append("home/chronos/test");

  base::FilePath prior_test = prior_log_dir_.Append("test");
  base::FilePath prior_test1 = prior_test.Append("test1");
  base::FilePath prior_test2 = prior_test.Append("test2");
  base::FilePath prior_standalone = prior_log_dir_.Append("standalone");
  base::FilePath prior_log1 = prior_log_dir_.Append("logs/log1");

  std::string preserve_str("#\n");
  preserve_str.append(test.value());
  preserve_str.append("\n");
  preserve_str.append(standalone.value());
  preserve_str.append("\n#ignore\n\n");
  preserve_str.append(var_logs.value());

  ASSERT_TRUE(CreateDirAndWriteFile(lab_preserve_logs_, preserve_str));
  ASSERT_TRUE(CreateDirAndWriteFile(test1, "#"));
  ASSERT_TRUE(CreateDirAndWriteFile(test2, "#"));
  ASSERT_TRUE(CreateDirAndWriteFile(standalone, "#"));
  ASSERT_TRUE(CreateDirAndWriteFile(log1, "#"));
  ASSERT_TRUE(CreateDirAndWriteFile(home_chronos, "#"));

  struct stat st;
  st.st_mode = S_IFREG;
  platform_->SetStatResultForPath(lab_preserve_logs_, st);

  EXPECT_EQ(PathExists(home_chronos), true);

  stateful_mount_->DevGatherLogs(base_dir);

  EXPECT_EQ(PathExists(prior_test1), true);
  EXPECT_EQ(PathExists(prior_test2), true);
  EXPECT_EQ(PathExists(prior_standalone), true);
  EXPECT_EQ(PathExists(prior_log1), true);
  EXPECT_EQ(PathExists(standalone), true);
  EXPECT_EQ(PathExists(lab_preserve_logs_), false);
}
