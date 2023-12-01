// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dev-install/dev_install.h"

#include <unistd.h>

#include <istream>
#include <sstream>
#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::Return;

namespace dev_install {

namespace {

class DevInstallMock : public DevInstall {
 public:
  MOCK_METHOD(bool, IsDevMode, (), (const, override));
  MOCK_METHOD(bool,
              PromptUser,
              (std::istream&, const std::string&),
              (override));
  MOCK_METHOD(bool, ClearStateDir, (const base::FilePath&), (override));
  MOCK_METHOD(bool,
              InitializeStateDir,
              (const base::FilePath& dir),
              (override));
  MOCK_METHOD(bool,
              DownloadAndInstallBootstrapPackages,
              (const base::FilePath&),
              (override));
  MOCK_METHOD(bool, ConfigurePortage, (), (override));
  MOCK_METHOD(bool, InstallExtraPackages, (), (override));
};

class DevInstallTest : public ::testing::Test {
 public:
  void SetUp() override {
    // Set the default to dev mode enabled.  Most tests want that.
    ON_CALL(dev_install_, IsDevMode()).WillByDefault(Return(true));

    // Ignore stateful setup for most tests.
    ON_CALL(dev_install_, InitializeStateDir(_)).WillByDefault(Return(true));

    // Ignore bootstrap for most tests.
    ON_CALL(dev_install_, DownloadAndInstallBootstrapPackages(_))
        .WillByDefault(Return(true));

    // Ignore portage setup for most tests.
    ON_CALL(dev_install_, ConfigurePortage()).WillByDefault(Return(true));

    // Ignore extra setup for most tests.
    ON_CALL(dev_install_, InstallExtraPackages()).WillByDefault(Return(true));

    // Most tests should run with a path that doesn't exist.
    dev_install_.SetStateDirForTest(base::FilePath("/.path-does-not-exist"));
  }

 protected:
  DevInstallMock dev_install_;
};

}  // namespace

// Check default run through.
TEST_F(DevInstallTest, Run) {
  EXPECT_EQ(0, dev_install_.Run());
}

// Systems not in dev mode should abort.
TEST_F(DevInstallTest, NonDevMode) {
  EXPECT_CALL(dev_install_, IsDevMode()).WillOnce(Return(false));
  EXPECT_CALL(dev_install_, ClearStateDir(_)).Times(0);
  EXPECT_EQ(2, dev_install_.Run());
}

// Check system has been initialized.
TEST_F(DevInstallTest, AlreadyInitialized) {
  dev_install_.SetStateDirForTest(base::FilePath("/"));
  ASSERT_EQ(4, dev_install_.Run());
}

// Check --reinstall passed.
TEST_F(DevInstallTest, RunReinstallWorked) {
  dev_install_.SetReinstallForTest(true);
  EXPECT_CALL(dev_install_, ClearStateDir(_)).WillOnce(Return(true));
  ASSERT_EQ(0, dev_install_.Run());
}

// Check when --reinstall is requested but clearing fails.
TEST_F(DevInstallTest, RunReinstallFails) {
  dev_install_.SetReinstallForTest(true);
  EXPECT_CALL(dev_install_, ClearStateDir(_)).WillOnce(Return(false));
  ASSERT_EQ(1, dev_install_.Run());
}

// Check --uninstall passed.
TEST_F(DevInstallTest, RunUninstall) {
  dev_install_.SetUninstallForTest(true);
  EXPECT_CALL(dev_install_, ClearStateDir(_)).WillOnce(Return(true));
  ASSERT_EQ(0, dev_install_.Run());
}

// Stateful setup failures.
TEST_F(DevInstallTest, StatefulSetupFailure) {
  EXPECT_CALL(dev_install_, InitializeStateDir(_)).WillOnce(Return(false));
  ASSERT_EQ(5, dev_install_.Run());
}

// We only bootstrap before exiting.
TEST_F(DevInstallTest, BootstrapOnly) {
  dev_install_.SetBootstrapForTest(true);
  ASSERT_EQ(0, dev_install_.Run());
}

// Bootstrap failures.
TEST_F(DevInstallTest, BootstrapFailure) {
  EXPECT_CALL(dev_install_, DownloadAndInstallBootstrapPackages(_))
      .WillOnce(Return(false));
  ASSERT_EQ(7, dev_install_.Run());
}

// Portage setup failures.
TEST_F(DevInstallTest, PortageFailure) {
  EXPECT_CALL(dev_install_, ConfigurePortage()).WillOnce(Return(false));
  ASSERT_EQ(8, dev_install_.Run());
}

// Extra package failures.
TEST_F(DevInstallTest, ExtraPackagesFailure) {
  EXPECT_CALL(dev_install_, InstallExtraPackages()).WillOnce(Return(false));
  ASSERT_EQ(9, dev_install_.Run());
}

namespace {

class PromptUserTest : public ::testing::Test {
 protected:
  DevInstall dev_install_;
};

}  // namespace

// The --yes flag should pass w/out prompting the user.
TEST_F(PromptUserTest, Forced) {
  dev_install_.SetYesForTest(true);
  std::stringstream stream("");
  EXPECT_TRUE(dev_install_.PromptUser(stream, ""));
}

// EOF input should fail.
TEST_F(PromptUserTest, Eof) {
  std::stringstream stream("");
  EXPECT_FALSE(dev_install_.PromptUser(stream, ""));
}

// Default input (hitting enter) should fail.
TEST_F(PromptUserTest, Default) {
  std::stringstream stream("\n");
  EXPECT_FALSE(dev_install_.PromptUser(stream, ""));
}

// Entering "n" should fail.
TEST_F(PromptUserTest, No) {
  std::stringstream stream("n\n");
  EXPECT_FALSE(dev_install_.PromptUser(stream, ""));
}

// Entering "y" should pass.
TEST_F(PromptUserTest, Yes) {
  std::stringstream stream("y\n");
  EXPECT_TRUE(dev_install_.PromptUser(stream, ""));
}

namespace {

class DeletePathTest : public ::testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_dir_ = scoped_temp_dir_.GetPath();
    dev_install_.SetStateDirForTest(test_dir_);
  }

 protected:
  DevInstall dev_install_;
  base::FilePath test_dir_;
  base::ScopedTempDir scoped_temp_dir_;
};

}  // namespace

// Check missing dir.
TEST_F(DeletePathTest, Missing) {
  struct stat st = {};
  EXPECT_TRUE(dev_install_.DeletePath(st, test_dir_.Append("foo")));
}

// Check deleting dir contents leaves the dir alone.
TEST_F(DeletePathTest, Empty) {
  struct stat st = {};
  EXPECT_TRUE(dev_install_.DeletePath(st, test_dir_));
  EXPECT_TRUE(base::PathExists(test_dir_));
}

// Check mounted deletion.
TEST_F(DeletePathTest, Mounted) {
  struct stat st = {};
  const base::FilePath subdir = test_dir_.Append("subdir");
  EXPECT_TRUE(base::CreateDirectory(subdir));
  EXPECT_FALSE(dev_install_.DeletePath(st, test_dir_));
  EXPECT_TRUE(base::PathExists(subdir));
}

// Check recursive deletion.
TEST_F(DeletePathTest, Works) {
  struct stat st;
  EXPECT_EQ(0, stat(test_dir_.value().c_str(), &st));

  EXPECT_EQ(3, base::WriteFile(test_dir_.Append("file"), "123", 3));
  EXPECT_EQ(0, symlink("x", test_dir_.Append("broken-sym").value().c_str()));
  EXPECT_EQ(0, symlink("file", test_dir_.Append("file-sym").value().c_str()));
  EXPECT_EQ(0, symlink(".", test_dir_.Append("dir-sym").value().c_str()));
  EXPECT_EQ(0, symlink("subdir", test_dir_.Append("dir-sym2").value().c_str()));
  const base::FilePath subdir = test_dir_.Append("subdir");
  EXPECT_TRUE(base::CreateDirectory(subdir));
  EXPECT_EQ(3, base::WriteFile(subdir.Append("file"), "123", 3));
  const base::FilePath subsubdir = test_dir_.Append("subdir");
  EXPECT_TRUE(base::CreateDirectory(subsubdir));
  EXPECT_EQ(3, base::WriteFile(subsubdir.Append("file"), "123", 3));

  EXPECT_TRUE(dev_install_.DeletePath(st, test_dir_));
  EXPECT_TRUE(base::PathExists(test_dir_));
  EXPECT_EQ(0, rmdir(test_dir_.value().c_str()));
}

namespace {

class CreateMissingDirectoryTest : public ::testing::Test {
 public:
  void SetUp() {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_dir_ = scoped_temp_dir_.GetPath();
  }

 protected:
  DevInstall dev_install_;
  base::FilePath test_dir_;
  base::ScopedTempDir scoped_temp_dir_;
};

}  // namespace

// Create dirs that don't yet exist.
TEST_F(CreateMissingDirectoryTest, Works) {
  const base::FilePath dir = test_dir_.Append("test");
  ASSERT_TRUE(dev_install_.CreateMissingDirectory(dir));
  int mode;
  ASSERT_TRUE(base::GetPosixFilePermissions(dir, &mode));
  ASSERT_EQ(0755, mode);
  ASSERT_TRUE(dev_install_.CreateMissingDirectory(dir));
}

// If a dir already exists, should do nothing.
TEST_F(CreateMissingDirectoryTest, Existing) {
  ASSERT_TRUE(dev_install_.CreateMissingDirectory(test_dir_));
  ASSERT_TRUE(dev_install_.CreateMissingDirectory(test_dir_));
}

namespace {

// We could mock out DeletePath, but it's easy to lightly validate it.
class ClearStateDirMock : public DevInstall {
 public:
  MOCK_METHOD(bool,
              PromptUser,
              (std::istream&, const std::string&),
              (override));
};

class ClearStateDirTest : public ::testing::Test {
 public:
  void SetUp() {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_dir_ = scoped_temp_dir_.GetPath();
  }

 protected:
  ClearStateDirMock dev_install_;
  base::FilePath test_dir_;
  base::ScopedTempDir scoped_temp_dir_;
};

}  // namespace

// Check user rejecting things.
TEST_F(ClearStateDirTest, Cancel) {
  EXPECT_CALL(dev_install_, PromptUser(_, _)).WillOnce(Return(false));
  const base::FilePath subdir = test_dir_.Append("subdir");
  ASSERT_TRUE(base::CreateDirectory(subdir));
  ASSERT_FALSE(dev_install_.ClearStateDir(test_dir_));
  ASSERT_TRUE(base::PathExists(subdir));
}

// Check missing dir is handled.
TEST_F(ClearStateDirTest, Missing) {
  EXPECT_CALL(dev_install_, PromptUser(_, _)).WillOnce(Return(true));
  ASSERT_TRUE(dev_install_.ClearStateDir(test_dir_.Append("subdir")));
  ASSERT_TRUE(base::PathExists(test_dir_));
}

// Check empty dir is handled.
TEST_F(ClearStateDirTest, Empty) {
  EXPECT_CALL(dev_install_, PromptUser(_, _)).WillOnce(Return(true));
  ASSERT_TRUE(dev_install_.ClearStateDir(test_dir_));
  ASSERT_TRUE(base::PathExists(test_dir_));
}

// Check dir with contents is cleared.
TEST_F(ClearStateDirTest, Works) {
  EXPECT_CALL(dev_install_, PromptUser(_, _)).WillOnce(Return(true));
  const base::FilePath subdir = test_dir_.Append("subdir");
  ASSERT_TRUE(base::CreateDirectory(subdir));
  ASSERT_TRUE(dev_install_.ClearStateDir(test_dir_));
  ASSERT_FALSE(base::PathExists(subdir));
}

namespace {

class InitializeStateDirTest : public ::testing::Test {
 public:
  void SetUp() {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_dir_ = scoped_temp_dir_.GetPath();
  }

 protected:
  DevInstall dev_install_;
  base::FilePath test_dir_;
  base::ScopedTempDir scoped_temp_dir_;
};

}  // namespace

// Check stateful is set up correctly.
TEST_F(InitializeStateDirTest, Works) {
  // Make sure we fully set things up.
  ASSERT_TRUE(dev_install_.InitializeStateDir(test_dir_));
  ASSERT_TRUE(base::IsLink(test_dir_.Append("usr")));
  ASSERT_TRUE(base::IsLink(test_dir_.Append("local")));
  ASSERT_TRUE(base::IsLink(test_dir_.Append("local")));
  const base::FilePath etc = test_dir_.Append("etc");
  ASSERT_TRUE(base::PathExists(etc));
  ASSERT_TRUE(base::IsLink(etc.Append("passwd")));
  ASSERT_TRUE(base::IsLink(etc.Append("group")));
  const base::FilePath tmp = test_dir_.Append("tmp");
  ASSERT_TRUE(base::PathExists(tmp));
  // Can't use base::GetPosixFilePermissions as that blocks +t mode.
  struct stat st;
  ASSERT_EQ(0, stat(tmp.value().c_str(), &st));
  ASSERT_EQ(01777, st.st_mode & 07777);

  // Calling a second time should be fine.
  ASSERT_TRUE(dev_install_.InitializeStateDir(test_dir_));
}

// Check we handle errors gracefully.
TEST_F(InitializeStateDirTest, Fails) {
  // Create a broken /etc symlink.
  ASSERT_TRUE(
      base::CreateSymbolicLink(base::FilePath("foo"), test_dir_.Append("etc")));
  ASSERT_FALSE(dev_install_.InitializeStateDir(test_dir_));
}

namespace {

class LoadRuntimeSettingsTest : public ::testing::Test {
 public:
  void SetUp() {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_dir_ = scoped_temp_dir_.GetPath();
  }

 protected:
  DevInstall dev_install_;
  base::FilePath test_dir_;
  base::ScopedTempDir scoped_temp_dir_;
};

}  // namespace

// Check loading state works.
TEST_F(LoadRuntimeSettingsTest, Works) {
  const base::FilePath lsb_release = test_dir_.Append("lsb-release");
  std::string data{
      "CHROMEOS_DEVSERVER=https://foo\n"
      "CHROMEOS_RELEASE_BOARD=betty\n"
      "CHROMEOS_RELEASE_CHROME_MILESTONE=79\n"
      "CHROMEOS_RELEASE_VERSION=100.10.1\n"};
  ASSERT_EQ(base::WriteFile(lsb_release, data.c_str(), data.size()),
            data.size());
  ASSERT_TRUE(dev_install_.LoadRuntimeSettings(lsb_release));
  ASSERT_EQ(dev_install_.GetDevserverUrlForTest(), "https://foo");
  ASSERT_EQ(dev_install_.GetBoardForTest(), "betty");
  ASSERT_EQ(dev_install_.GetBinhostVersionForTest(), "100.10.1");
}

// Check loading empty state works.
TEST_F(LoadRuntimeSettingsTest, Empty) {
  const base::FilePath lsb_release = test_dir_.Append("lsb-release");
  std::string data{""};
  ASSERT_EQ(base::WriteFile(lsb_release, data.c_str(), data.size()),
            data.size());
  ASSERT_TRUE(dev_install_.LoadRuntimeSettings(lsb_release));
}

// Check loading state doesn't abort with missing file.
TEST_F(LoadRuntimeSettingsTest, Missing) {
  ASSERT_TRUE(dev_install_.LoadRuntimeSettings(test_dir_.Append("asdf")));
}

namespace {

class BootstrapPackagesMock : public DevInstall {
 public:
  MOCK_METHOD(bool,
              DownloadAndInstallBootstrapPackage,
              (const std::string&),
              (override));
};

class BootstrapPackagesTest : public ::testing::Test {
 public:
  void SetUp() {
    // Have the install step pass by default.
    ON_CALL(dev_install_, DownloadAndInstallBootstrapPackage(_))
        .WillByDefault(Return(true));

    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_dir_ = scoped_temp_dir_.GetPath();
    dev_install_.SetStateDirForTest(test_dir_);
  }

 protected:
  BootstrapPackagesMock dev_install_;
  base::FilePath test_dir_;
  base::ScopedTempDir scoped_temp_dir_;
};

}  // namespace

// Check bootstrap works in general.
TEST_F(BootstrapPackagesTest, Works) {
  const base::FilePath listing = test_dir_.Append("bootstrap.packages");
  std::string data{
      "foo/bar-123\n"
      "cat/pkg-1.0\n"};
  ASSERT_EQ(base::WriteFile(listing, data.c_str(), data.size()), data.size());

  ON_CALL(dev_install_, DownloadAndInstallBootstrapPackage(_))
      .WillByDefault(Return(false));
  EXPECT_CALL(dev_install_, DownloadAndInstallBootstrapPackage("foo/bar-123"))
      .WillOnce(Return(true));
  EXPECT_CALL(dev_install_, DownloadAndInstallBootstrapPackage("cat/pkg-1.0"))
      .WillOnce(Return(true));

  const base::FilePath bindir = test_dir_.Append("usr/bin");
  ASSERT_TRUE(base::CreateDirectory(bindir));
  ASSERT_TRUE(dev_install_.DownloadAndInstallBootstrapPackages(listing));

  // We assert the symlinks exist.  We assume the targets are valid for now.
  base::FilePath target;
  ASSERT_TRUE(base::ReadSymbolicLink(bindir.Append("python"), &target));
  ASSERT_TRUE(base::ReadSymbolicLink(bindir.Append("python2"), &target));
  ASSERT_TRUE(base::ReadSymbolicLink(bindir.Append("python3"), &target));
}

// Check missing bootstrap list fails.
TEST_F(BootstrapPackagesTest, Missing) {
  const base::FilePath listing = test_dir_.Append("bootstrap.packages");
  ASSERT_FALSE(dev_install_.DownloadAndInstallBootstrapPackages(listing));
}

// Check empty bootstrap list fails.
TEST_F(BootstrapPackagesTest, Empty) {
  const base::FilePath listing = test_dir_.Append("bootstrap.packages");
  ASSERT_EQ(base::WriteFile(listing, "", 0), 0);
  ASSERT_FALSE(dev_install_.DownloadAndInstallBootstrapPackages(listing));
}

// Check mid-bootstrap failure behavior.
TEST_F(BootstrapPackagesTest, PackageFailed) {
  const base::FilePath listing = test_dir_.Append("bootstrap.packages");
  std::string data{"cat/pkg-3"};
  ASSERT_EQ(base::WriteFile(listing, data.c_str(), data.size()), data.size());

  EXPECT_CALL(dev_install_, DownloadAndInstallBootstrapPackage("cat/pkg-3"))
      .WillOnce(Return(false));

  const base::FilePath bindir = test_dir_.Append("usr/bin");
  ASSERT_TRUE(base::CreateDirectory(bindir));
  ASSERT_FALSE(dev_install_.DownloadAndInstallBootstrapPackages(listing));
}

namespace {

class ConfigurePortageTest : public ::testing::Test {
 public:
  void SetUp() {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_dir_ = scoped_temp_dir_.GetPath();
    dev_install_.SetStateDirForTest(test_dir_);
  }

 protected:
  BootstrapPackagesMock dev_install_;
  base::FilePath test_dir_;
  base::ScopedTempDir scoped_temp_dir_;
};

}  // namespace

// Check setup works in general.
TEST_F(ConfigurePortageTest, Works) {
  std::string data;

  // The exact path doesn't matter here, but we create a deep one to mimic
  // common scenarios on real devices.
  const auto portage_internal_dir = test_dir_.Append(
      "lib64/python3.6/site-packages/portage/package/ebuild/_config");
  const auto portage_internal_file =
      portage_internal_dir.Append("special_env_vars.py");
  ASSERT_TRUE(base::CreateDirectory(portage_internal_dir));
  data = "foo\nenviron_whitelist = []\n\nbar\n";
  ASSERT_TRUE(base::WriteFile(portage_internal_file, data.data(), data.size()));

  // Create a symlink to mimic real devices to detect recursive search issues.
  ASSERT_EQ(0, symlink(".", test_dir_.Append("usr").value().c_str()));
  ASSERT_EQ(0, symlink(".", test_dir_.Append("local").value().c_str()));

  // Check basic profile setup worked.
  EXPECT_TRUE(dev_install_.ConfigurePortage());
  const base::FilePath portage_dir = test_dir_.Append("etc/portage");
  EXPECT_TRUE(base::PathExists(portage_dir));

  // Verify make.conf has valid ROOT= setting.
  EXPECT_TRUE(base::ReadFileToString(portage_dir.Append("make.conf"), &data));
  EXPECT_NE(data.find("ROOT=\"" + test_dir_.value() + "\"\n"),
            std::string::npos);

  // Check internal portage hacking.
  EXPECT_TRUE(base::ReadFileToString(portage_internal_file, &data));
  EXPECT_EQ(data, "foo\nenviron_whitelist = ['LD_LIBRARY_PATH']\n\nbar\n");
}

}  // namespace dev_install
