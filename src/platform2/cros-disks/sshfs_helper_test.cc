// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/sshfs_helper.h"

#include <sys/stat.h>

#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/process/process_reaper.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cros-disks/fuse_mounter.h"
#include "cros-disks/mount_options.h"
#include "cros-disks/platform.h"
#include "cros-disks/uri.h"

using testing::_;
using testing::AllOf;
using testing::EndsWith;
using testing::HasSubstr;
using testing::IsSupersetOf;
using testing::Not;
using testing::Return;
using testing::StartsWith;
using testing::StrEq;
using testing::UnorderedElementsAre;

namespace cros_disks {

namespace {

const uid_t kMountUID = 200;
const gid_t kMountGID = 201;
const base::FilePath kWorkingDir("/wkdir");
const base::FilePath kMountDir("/mnt");
const Uri kSomeSource("sshfs", "src");
const Uri kSftpSource("sftp", "33:4321");

std::vector<std::string> ParseOptions(const SandboxedProcess& sandbox,
                                      bool sshfs) {
  CHECK_EQ(3, sandbox.arguments().size());
  if (sshfs) {
    CHECK_EQ("src", sandbox.arguments()[0]);
  }
  CHECK_EQ("-o", sandbox.arguments()[1]);
  return base::SplitString(sandbox.arguments()[2], ",",
                           base::WhitespaceHandling::KEEP_WHITESPACE,
                           base::SplitResult::SPLIT_WANT_ALL);
}

// Mock Platform implementation for testing.
class MockPlatform : public Platform {
 public:
  MockPlatform() = default;

  bool GetUserAndGroupId(const std::string& user,
                         uid_t* user_id,
                         gid_t* group_id) const override {
    if (user == "fuse-sshfs") {
      if (user_id)
        *user_id = kMountUID;
      if (group_id)
        *group_id = kMountGID;
      return true;
    }
    return false;
  }

  MOCK_METHOD(bool,
              SetOwnership,
              (const std::string&, uid_t, gid_t),
              (const, override));
};

}  // namespace

class SshfsHelperTest : public ::testing::Test {
 public:
  SshfsHelperTest() {
    ON_CALL(platform_, SetOwnership(_, kMountUID, getgid()))
        .WillByDefault(Return(true));
    ON_CALL(platform_, SetOwnership(_, kMountUID, kMountGID))
        .WillByDefault(Return(true));
  }

  void SetUp() override {
    CHECK(working_dir_.CreateUniqueTempDir());
    helper_ = std::make_unique<SshfsHelper>(&platform_, &process_reaper_,
                                            working_dir_.GetPath());
  }

 protected:
  MountError ConfigureSandbox(const std::string& source,
                              std::vector<std::string> params,
                              std::vector<std::string>* args) {
    FakeSandboxedProcess sandbox;
    MountError error = helper_->ConfigureSandbox(source, kMountDir,
                                                 std::move(params), &sandbox);
    if (error == MountError::kSuccess) {
      *args = ParseOptions(sandbox, source.substr(0, 5) == "sshfs");
    }
    return error;
  }

  MockPlatform platform_;
  brillo::ProcessReaper process_reaper_;
  base::ScopedTempDir working_dir_;
  std::unique_ptr<SshfsHelper> helper_;
};

TEST_F(SshfsHelperTest, ConfigureSandbox) {
  EXPECT_CALL(platform_, SetOwnership(EndsWith("id"), kMountUID, kMountGID))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_,
              SetOwnership(EndsWith("known_hosts"), kMountUID, kMountGID))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_,
              SetOwnership(StartsWith(working_dir_.GetPath().value()),
                           kMountUID, getgid()))
      .WillOnce(Return(true));

  std::vector<std::string> args;
  EXPECT_EQ(
      MountError::kSuccess,
      ConfigureSandbox(
          kSomeSource.value(),
          {"IdentityBase64=YWJjCg==", "UserKnownHostsBase64=MTIzNDUK"}, &args));

  EXPECT_THAT(
      args,
      UnorderedElementsAre(
          "KbdInteractiveAuthentication=no", "PasswordAuthentication=no",
          "BatchMode=yes", "follow_symlinks", "cache=no", "uid=1000",
          "gid=1001",
          AllOf(StartsWith("IdentityFile=" + working_dir_.GetPath().value()),
                EndsWith("/id")),
          AllOf(StartsWith("UserKnownHostsFile=" +
                           working_dir_.GetPath().value()),
                EndsWith("/known_hosts"))));

  std::string id_path;
  ASSERT_TRUE(GetParamValue(args, "IdentityFile", &id_path));
  std::string hosts_path;
  ASSERT_TRUE(GetParamValue(args, "UserKnownHostsFile", &hosts_path));

  base::stat_wrapper_t stat;
  EXPECT_EQ(0, base::File::Stat(id_path.c_str(), &stat));
  EXPECT_EQ(0600, stat.st_mode & 0777);
  EXPECT_EQ(0, base::File::Stat(hosts_path.c_str(), &stat));
  EXPECT_EQ(0600, stat.st_mode & 0777);
  base::FilePath dir = base::FilePath(id_path).DirName();
  EXPECT_EQ(0, base::File::Stat(dir.value().c_str(), &stat));
  EXPECT_EQ(0770, stat.st_mode & 0777);

  std::string data;
  ASSERT_TRUE(base::ReadFileToString(base::FilePath(id_path), &data));
  EXPECT_EQ("abc\n", data);
  ASSERT_TRUE(base::ReadFileToString(base::FilePath(hosts_path), &data));
  EXPECT_EQ("12345\n", data);
}

TEST_F(SshfsHelperTest, ConfigureSandboxWithHostAndPort) {
  std::vector<std::string> args;
  EXPECT_EQ(MountError::kSuccess,
            ConfigureSandbox(
                kSomeSource.value(),
                {"IdentityBase64=YWJjCg==", "UserKnownHostsBase64=MTIzNDUK",
                 "HostName=foobar", "Port=1234"},
                &args));

  EXPECT_THAT(args,
              IsSupersetOf({StrEq("HostName=foobar"), StrEq("Port=1234")}));
}

TEST_F(SshfsHelperTest, ConfigureSandboxFailsWithInvalidSource) {
  EXPECT_CALL(platform_, SetOwnership).Times(0);
  std::vector<std::string> args;
  EXPECT_NE(
      MountError::kSuccess,
      ConfigureSandbox(
          "foo://bar",
          {"IdentityBase64=YWJjCg==", "UserKnownHostsBase64=MTIzNDUK"}, &args));
}

TEST_F(SshfsHelperTest, ConfigureSandboxFailsWithoutId) {
  EXPECT_CALL(platform_, SetOwnership).Times(0);
  std::vector<std::string> args;
  EXPECT_NE(MountError::kSuccess,
            ConfigureSandbox(kSomeSource.value(),
                             {"UserKnownHostsBase64=MTIzNDUK"}, &args));
}

TEST_F(SshfsHelperTest, ConfigureSandboxFailsWithoutKnownHosts) {
  EXPECT_CALL(platform_, SetOwnership).Times(0);
  std::vector<std::string> args;
  EXPECT_NE(MountError::kSuccess,
            ConfigureSandbox(kSomeSource.value(), {"IdentityBase64=YWJjCg=="},
                             &args));
}

TEST_F(SshfsHelperTest, ConfigureSandboxFailsWithoutDir) {
  EXPECT_CALL(platform_, SetOwnership).Times(0);
  ASSERT_TRUE(working_dir_.Delete());
  std::vector<std::string> args;
  EXPECT_NE(
      MountError::kSuccess,
      ConfigureSandbox(
          kSomeSource.value(),
          {"IdentityBase64=YWJjCg==", "UserKnownHostsBase64=MTIzNDUK"}, &args));
}

// Verifies that CanMount correctly identifies handleable URIs.
TEST_F(SshfsHelperTest, CanMount) {
  base::FilePath name;

  EXPECT_TRUE(helper_->CanMount("sshfs://foo", {}, &name));
  EXPECT_EQ("foo", name.value());
  EXPECT_TRUE(helper_->CanMount("sshfs://", {}, &name));
  EXPECT_EQ("sshfs", name.value());
  EXPECT_TRUE(helper_->CanMount("sshfs://usr@host.com:", {}, &name));
  EXPECT_EQ("usr@host_com:", name.value());
  EXPECT_TRUE(helper_->CanMount("sshfs://host:/some/path/..", {}, &name));
  EXPECT_EQ("host:$some$path$__", name.value());
  EXPECT_TRUE(helper_->CanMount("sftp://32:1234", {}, &name));
  EXPECT_EQ("32:1234", name.value());

  EXPECT_FALSE(helper_->CanMount("sshfss://foo", {}, &name));
  EXPECT_FALSE(helper_->CanMount("ssh://foo", {}, &name));
}

TEST_F(SshfsHelperTest, ConfigureSandboxWithCidAndPort) {
  std::vector<std::string> args;
  EXPECT_EQ(MountError::kSuccess,
            ConfigureSandbox(Uri("sftp", "32:1234").value(), {}, &args));

  EXPECT_THAT(args, IsSupersetOf({StrEq("vsock=32:1234")}));
}

}  // namespace cros_disks
