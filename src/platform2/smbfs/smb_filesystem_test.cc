// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/smb_filesystem.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <utility>

#include <base/run_loop.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "smbfs/samba_interface_impl.h"
#include "smbfs/smb_credential.h"

namespace smbfs {
namespace {

using ::testing::_;

constexpr char kSharePath[] = "smb://server/share";
constexpr char kUsername[] = "my-username";

class MockDelegate : public SmbFilesystem::Delegate {
 public:
  MOCK_METHOD(void,
              RequestCredentials,
              (RequestCredentialsCallback),
              (override));
};

class MockSambaInterface : public SambaInterfaceImpl {
 public:
  MOCK_METHOD(void,
              UpdateCredentials,
              (std::unique_ptr<SmbCredential>),
              (override));
};

class TestSmbFilesystem : public SmbFilesystem {
 public:
  TestSmbFilesystem()
      : SmbFilesystem(&mock_delegate_, kSharePath),
        mock_samba_impl_(new MockSambaInterface()) {
    SetSambaInterface(std::unique_ptr<SambaInterface>(mock_samba_impl_));
  }

  MockDelegate& delegate() { return mock_delegate_; }
  MockSambaInterface* samba_impl() { return mock_samba_impl_; }

 private:
  MockDelegate mock_delegate_;
  MockSambaInterface* mock_samba_impl_;
};

}  // namespace

class SmbFilesystemTest : public testing::Test {
 protected:
  base::test::TaskEnvironment task_environment{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY,
      base::test::TaskEnvironment::MainThreadType::IO};
};

TEST_F(SmbFilesystemTest, SetResolvedAddress) {
  TestSmbFilesystem fs;

  // Initial value is share path.
  EXPECT_EQ(kSharePath, fs.resolved_share_path());

  fs.SetResolvedAddress({1, 2, 3, 4});
  EXPECT_EQ("smb://1.2.3.4/share", fs.resolved_share_path());
  fs.SetResolvedAddress({127, 0, 0, 1});
  EXPECT_EQ("smb://127.0.0.1/share", fs.resolved_share_path());

  // Invalid address does nothing.
  fs.SetResolvedAddress({1, 2, 3});
  EXPECT_EQ("smb://127.0.0.1/share", fs.resolved_share_path());

  // Empty address resets to original share path.
  fs.SetResolvedAddress({});
  EXPECT_EQ(kSharePath, fs.resolved_share_path());
}

TEST_F(SmbFilesystemTest, MakeStatModeBits) {
  TestSmbFilesystem fs;

  // Check: "Other" permission bits are cleared.
  mode_t in_mode = S_IRWXO;
  mode_t out_mode = fs.MakeStatModeBits(in_mode);
  EXPECT_EQ(0, out_mode);

  // Check: Directories have user execute bit set.
  in_mode = S_IFDIR;
  out_mode = fs.MakeStatModeBits(in_mode);
  EXPECT_TRUE(out_mode & S_IXUSR);

  // Check: Files do not have user execute bit set.
  in_mode = S_IFREG;
  out_mode = fs.MakeStatModeBits(in_mode);
  EXPECT_FALSE(out_mode & S_IXUSR);

  // Check: Group bits equal user bits.
  in_mode = S_IRUSR | S_IWUSR;
  out_mode = fs.MakeStatModeBits(in_mode);
  EXPECT_EQ(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP, out_mode);
}

TEST_F(SmbFilesystemTest, MaybeUpdateCredentials_NoRequest) {
  TestSmbFilesystem fs;

  EXPECT_CALL(fs.delegate(), RequestCredentials(_)).Times(0);
  fs.MaybeUpdateCredentials(EBUSY);
  base::RunLoop().RunUntilIdle();
}

TEST_F(SmbFilesystemTest, MaybeUpdateCredentials_RequestOnEPERM) {
  TestSmbFilesystem fs;

  base::RunLoop run_loop;
  EXPECT_CALL(fs.delegate(), RequestCredentials(_))
      .WillOnce([&](MockDelegate::RequestCredentialsCallback callback) {
        std::move(callback).Run(std::make_unique<SmbCredential>(
            "" /* workgroup */, kUsername, nullptr));
        run_loop.Quit();
      });
  EXPECT_CALL(*(fs.samba_impl()), UpdateCredentials(_)).Times(1);
  fs.MaybeUpdateCredentials(EPERM);
  run_loop.Run();
}

TEST_F(SmbFilesystemTest, MaybeUpdateCredentials_RequestOnEACCES) {
  TestSmbFilesystem fs;

  base::RunLoop run_loop;
  EXPECT_CALL(fs.delegate(), RequestCredentials(_))
      .WillOnce([&](MockDelegate::RequestCredentialsCallback callback) {
        std::move(callback).Run(std::make_unique<SmbCredential>(
            "" /* workgroup */, kUsername, nullptr));
        run_loop.Quit();
      });
  EXPECT_CALL(*(fs.samba_impl()), UpdateCredentials(_)).Times(1);
  fs.MaybeUpdateCredentials(EACCES);
  run_loop.Run();
}

TEST_F(SmbFilesystemTest, MaybeUpdateCredentials_NoDelegate) {
  TestSmbFilesystem fs;

  fs.MaybeUpdateCredentials(EPERM);
  base::RunLoop().RunUntilIdle();
}

TEST_F(SmbFilesystemTest, MaybeUpdateCredentials_OnlyOneRequest) {
  TestSmbFilesystem fs;

  EXPECT_CALL(fs.delegate(), RequestCredentials(_)).Times(1);
  fs.MaybeUpdateCredentials(EACCES);
  fs.MaybeUpdateCredentials(EACCES);
  base::RunLoop().RunUntilIdle();
}

TEST_F(SmbFilesystemTest, MaybeUpdateCredentials_IgnoreEmptyResponse) {
  TestSmbFilesystem fs;

  base::RunLoop run_loop;
  EXPECT_CALL(fs.delegate(), RequestCredentials(_))
      .WillOnce([&](MockDelegate::RequestCredentialsCallback callback) {
        std::move(callback).Run(nullptr);
        run_loop.Quit();
      });
  EXPECT_CALL(*(fs.samba_impl()), UpdateCredentials(_)).Times(0);
  fs.MaybeUpdateCredentials(EACCES);
  run_loop.Run();
}

}  // namespace smbfs
