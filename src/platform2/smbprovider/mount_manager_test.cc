// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <utility>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/test/simple_test_tick_clock.h>
#include <gtest/gtest.h>

#include "smbprovider/fake_samba_interface.h"
#include "smbprovider/fake_samba_proxy.h"
#include "smbprovider/mount_config.h"
#include "smbprovider/mount_manager.h"
#include "smbprovider/smbprovider_test_helper.h"
#include "smbprovider/temp_file_manager.h"

namespace smbprovider {
namespace {

constexpr char kMountRoot[] = "smb://192.168.0.1/test";
constexpr char kWorkgroup[] = "domain";
constexpr char kUsername[] = "user1";
constexpr char kPassword[] = "admin";

constexpr int32_t kBufferSize = 256;
}  // namespace

class MountManagerTest : public testing::Test {
 public:
  std::unique_ptr<SambaInterface> SambaInterfaceFactoryFunction(
      FakeSambaInterface* fake_samba,
      MountManager* mount_manager,
      const MountConfig& mount_config) {
    enable_ntlm_ = mount_config.enable_ntlm;
    return std::make_unique<FakeSambaProxy>(fake_samba);
  }

  MountManagerTest() {
    auto tick_clock = std::make_unique<base::SimpleTestTickClock>();

    auto mount_tracker = std::make_unique<MountTracker>(
        std::move(tick_clock), false /* metadata_cache_enabled */);

    auto fake_samba_ = std::make_unique<FakeSambaInterface>();
    auto samba_interface_factory =
        base::BindRepeating(&MountManagerTest::SambaInterfaceFactoryFunction,
                            base::Unretained(this), fake_samba_.get());

    mounts_ = std::make_unique<MountManager>(std::move(mount_tracker),
                                             samba_interface_factory);
  }
  MountManagerTest(const MountManagerTest&) = delete;
  MountManagerTest& operator=(const MountManagerTest&) = delete;

  ~MountManagerTest() override = default;

  void AddMount(const std::string& root_path, int32_t* mount_id) {
    AddMount(root_path, SmbCredential(), mount_id);
  }

  void AddMount(const std::string& root_path,
                SmbCredential credential,
                int32_t* mount_id) {
    mounts_->AddMount(root_path, std::move(credential),
                      MountConfig(true /* enable_ntlm */), mount_id);
  }

  void AddMountWithMountConfig(const std::string& root_path,
                               SmbCredential credential,
                               const MountConfig& mount_config,
                               int32_t* mount_id) {
    mounts_->AddMount(root_path, std::move(credential), mount_config, mount_id);
  }

  void ExpectCredentialsEqual(int32_t mount_id,
                              const std::string& root_path,
                              const std::string& workgroup,
                              const std::string& username,
                              const std::string& password) {
    smbprovider::ExpectCredentialsEqual(mounts_.get(), mount_id, root_path,
                                        workgroup, username, password);
  }

  SmbCredential CreateCredential(const std::string& workgroup,
                                 const std::string& username,
                                 const std::string& password,
                                 const base::FilePath& password_file = {}) {
    base::ScopedFD password_fd = WritePasswordToFile(&temp_files_, password);
    return SmbCredential(workgroup, username, GetPassword(password_fd),
                         password_file);
  }

 protected:
  bool GetRootPath(int32_t mount_id, std::string* mount_path) const {
    return mounts_->GetFullPath(mount_id, "" /* entry_path */, mount_path);
  }

  std::unique_ptr<MountManager> mounts_;
  TempFileManager temp_files_;
  bool enable_ntlm_ = false;
};

TEST_F(MountManagerTest, TestEmptyManager) {
  // Verify the state of an empty |MountManager|
  EXPECT_EQ(0, mounts_->MountCount());
  EXPECT_FALSE(mounts_->RemoveMount(0 /* mount_id */));
  EXPECT_EQ(0, mounts_->MountCount());
  EXPECT_FALSE(mounts_->IsAlreadyMounted(0 /* mount_id */));

  std::string full_path;
  EXPECT_FALSE(mounts_->GetFullPath(0 /* mount_id */, "foo.txt", &full_path));
}

TEST_F(MountManagerTest, TestAddRemoveMount) {
  // Add a new mount.
  const std::string root_path = "smb://server/share";
  int32_t mount_id;

  AddMount(root_path, &mount_id);

  // Verify the mount was added with a valid id.
  EXPECT_GE(mount_id, 0);
  EXPECT_EQ(1, mounts_->MountCount());
  EXPECT_TRUE(mounts_->IsAlreadyMounted(mount_id));

  // Verify the mount can be removed.
  EXPECT_TRUE(mounts_->RemoveMount(mount_id));
  EXPECT_EQ(0, mounts_->MountCount());
  EXPECT_FALSE(mounts_->IsAlreadyMounted(mount_id));
}

TEST_F(MountManagerTest, TestAddThenRemoveWrongMount) {
  // Add a new mount.
  const std::string root_path = "smb://server/share";
  int32_t mount_id;

  AddMount(root_path, &mount_id);

  // Verify RemoveMount fails with an invalid id and nothing is removed.
  const int32_t invalid_mount_id = mount_id + 1;
  EXPECT_FALSE(mounts_->IsAlreadyMounted(invalid_mount_id));
  EXPECT_FALSE(mounts_->RemoveMount(invalid_mount_id));
  EXPECT_EQ(1, mounts_->MountCount());
  EXPECT_TRUE(mounts_->IsAlreadyMounted(mount_id));

  // Verify the valid id can still be removed.
  EXPECT_TRUE(mounts_->RemoveMount(mount_id));
  EXPECT_EQ(0, mounts_->MountCount());
  EXPECT_FALSE(mounts_->IsAlreadyMounted(mount_id));
}

TEST_F(MountManagerTest, TestAddRemoveMultipleMounts) {
  // For this test it doesn't matter if the same root is used for both
  // mounts.
  const std::string root_path1 = "smb://server/share1";
  const std::string root_path2 = "smb://server/share2";

  // Add two mounts and verify they were both added.
  int32_t mount_id_1;
  int32_t mount_id_2;

  AddMount(root_path1, &mount_id_1);
  AddMount(root_path2, &mount_id_2);

  EXPECT_EQ(2, mounts_->MountCount());
  EXPECT_TRUE(mounts_->IsAlreadyMounted(mount_id_1));
  EXPECT_TRUE(mounts_->IsAlreadyMounted(mount_id_2));

  // Verify the ids are valid and different.
  EXPECT_GE(mount_id_1, 0);
  EXPECT_GE(mount_id_2, 0);
  EXPECT_NE(mount_id_1, mount_id_2);

  // Remove the second id, verify it is removed, and the first remains.
  EXPECT_TRUE(mounts_->RemoveMount(mount_id_2));
  EXPECT_EQ(1, mounts_->MountCount());
  EXPECT_FALSE(mounts_->IsAlreadyMounted(mount_id_2));
  EXPECT_TRUE(mounts_->IsAlreadyMounted(mount_id_1));

  // Remove the first id and verify it is also removed.
  EXPECT_TRUE(mounts_->RemoveMount(mount_id_1));
  EXPECT_EQ(0, mounts_->MountCount());
  EXPECT_FALSE(mounts_->IsAlreadyMounted(mount_id_1));
}

TEST_F(MountManagerTest, TestGetFullPath) {
  // Add a new mount.
  const std::string root_path = "smb://server/share";
  int32_t mount_id;

  AddMount(root_path, &mount_id);

  // Verify the full path is as expected.
  const std::string entry_path = "/foo/bar";
  const std::string expected_full_path = root_path + entry_path;
  std::string actual_full_path;
  EXPECT_TRUE(mounts_->GetFullPath(mount_id, entry_path, &actual_full_path));
  EXPECT_EQ(expected_full_path, actual_full_path);
}

TEST_F(MountManagerTest, TestGetCacheNoMounts) {
  MetadataCache* cache = nullptr;

  EXPECT_FALSE(mounts_->GetMetadataCache(0, &cache));
}

TEST_F(MountManagerTest, TestGetCache) {
  int32_t mount_id;
  AddMount("smb://server/share", &mount_id);

  MetadataCache* cache = nullptr;
  EXPECT_TRUE(mounts_->GetMetadataCache(mount_id, &cache));
  EXPECT_NE(nullptr, cache);
}

TEST_F(MountManagerTest, TestGetCacheForInvalidMount) {
  int32_t mount_id;
  AddMount("smb://server/share", &mount_id);

  // mount_id + 1 does not exist.
  MetadataCache* cache = nullptr;
  EXPECT_FALSE(mounts_->GetMetadataCache(mount_id + 1, &cache));
}

TEST_F(MountManagerTest, TestGetFullPathWithInvalidId) {
  // Add a new mount.
  const std::string root_path = "smb://server/share";
  int32_t mount_id;

  AddMount(root_path, &mount_id);

  // Verify calling GetFullPath() with an invalid id fails.
  const int32_t invalid_mount_id = mount_id + 1;
  EXPECT_FALSE(mounts_->IsAlreadyMounted(invalid_mount_id));
  std::string full_path;
  EXPECT_FALSE(mounts_->GetFullPath(invalid_mount_id, "/foo/bar", &full_path));
}

TEST_F(MountManagerTest, TestGetFullPathMultipleMounts) {
  // Add two mounts with different roots.
  const std::string root_path_1 = "smb://server/share1";
  const std::string root_path_2 = "smb://server/share2";
  ASSERT_NE(root_path_1, root_path_2);
  int32_t mount_id_1;
  int32_t mount_id_2;

  AddMount(root_path_1, &mount_id_1);
  AddMount(root_path_2, &mount_id_2);

  // Verify correct ids map to the correct paths.
  std::string actual_full_path;
  const std::string entry_path = "/foo/bar";
  const std::string expected_full_path_1 = root_path_1 + entry_path;
  const std::string expected_full_path_2 = root_path_2 + entry_path;
  EXPECT_TRUE(mounts_->GetFullPath(mount_id_1, entry_path, &actual_full_path));
  EXPECT_EQ(expected_full_path_1, actual_full_path);
  EXPECT_TRUE(mounts_->GetFullPath(mount_id_2, entry_path, &actual_full_path));
  EXPECT_EQ(expected_full_path_2, actual_full_path);
}

TEST_F(MountManagerTest, TestGetRelativePath) {
  const std::string root_path = "smb://server/share1";
  int32_t mount_id;

  AddMount(root_path, &mount_id);

  const std::string full_path = "smb://server/share1/animals/dog.jpg";
  const std::string expected_relative_path = "/animals/dog.jpg";

  EXPECT_EQ(expected_relative_path,
            mounts_->GetRelativePath(mount_id, full_path));
}

TEST_F(MountManagerTest, TestGetRelativePathOnRoot) {
  const std::string root_path = "smb://server/share1";
  int32_t mount_id;

  AddMount(root_path, &mount_id);

  const std::string full_path = "smb://server/share1/";
  const std::string expected_relative_path = "/";

  EXPECT_EQ(expected_relative_path,
            mounts_->GetRelativePath(mount_id, full_path));
}

TEST_F(MountManagerTest, TestAddMountWithCredential) {
  const std::string root_path = "smb://server/share1";
  const std::string workgroup = "google";
  const std::string username = "user1";
  const std::string password = "admin";
  int32_t mount_id;

  SmbCredential credential = CreateCredential(workgroup, username, password);
  AddMount(root_path, std::move(credential), &mount_id);

  EXPECT_GE(mount_id, 0);
  EXPECT_EQ(1, mounts_->MountCount());
  EXPECT_TRUE(mounts_->IsAlreadyMounted(mount_id));

  ExpectCredentialsEqual(mount_id, root_path, workgroup, username, password);
}

TEST_F(MountManagerTest, TestAddMountWithEmptyCredential) {
  const std::string root_path = "smb://server/share1";
  const std::string workgroup = "";
  const std::string username = "";
  const std::string password = "";
  int32_t mount_id;

  AddMount(root_path, &mount_id);

  EXPECT_GE(mount_id, 0);
  EXPECT_EQ(1, mounts_->MountCount());
  EXPECT_TRUE(mounts_->IsAlreadyMounted(mount_id));
  ExpectCredentialsEqual(mount_id, root_path, workgroup, username, password);
}

TEST_F(MountManagerTest, TestAddMountWithoutWorkgroup) {
  const std::string root_path = "smb://server/share1";
  const std::string workgroup = "";
  const std::string username = "user1";
  const std::string password = "admin";
  int32_t mount_id;

  SmbCredential credential = CreateCredential(workgroup, username, password);

  AddMount(root_path, std::move(credential), &mount_id);

  EXPECT_GE(mount_id, 0);
  EXPECT_EQ(1, mounts_->MountCount());
  EXPECT_TRUE(mounts_->IsAlreadyMounted(mount_id));

  ExpectCredentialsEqual(mount_id, root_path, workgroup, username, password);
}

TEST_F(MountManagerTest, TestAddMountWithEmptyPassword) {
  const std::string root_path = "smb://server/share1";
  const std::string workgroup = "google";
  const std::string username = "user1";
  const std::string password = "";
  int32_t mount_id;

  SmbCredential credential = CreateCredential(workgroup, username, password);
  AddMount(root_path, std::move(credential), &mount_id);

  EXPECT_GE(mount_id, 0);
  EXPECT_EQ(1, mounts_->MountCount());
  EXPECT_TRUE(mounts_->IsAlreadyMounted(mount_id));

  ExpectCredentialsEqual(mount_id, root_path, workgroup, username, password);
}

TEST_F(MountManagerTest, TestAddSameMount) {
  const std::string workgroup2 = "workgroup2";
  const std::string username2 = "user2";
  const std::string password2 = "root2";
  int32_t mount_id;

  SmbCredential credential = CreateCredential(kWorkgroup, kUsername, kPassword);

  AddMount(kMountRoot, std::move(credential), &mount_id);

  EXPECT_EQ(1, mounts_->MountCount());

  SmbCredential credential2 =
      CreateCredential(workgroup2, username2, password2);

  int32_t mount_id2;
  AddMount(kMountRoot, std::move(credential2), &mount_id2);
  EXPECT_EQ(2, mounts_->MountCount());
  EXPECT_TRUE(mounts_->IsAlreadyMounted(mount_id2));

  ExpectCredentialsEqual(mount_id, kMountRoot, kWorkgroup, kUsername,
                         kPassword);
  ExpectCredentialsEqual(mount_id2, kMountRoot, workgroup2, username2,
                         password2);
  EXPECT_NE(mount_id, mount_id2);
}

TEST_F(MountManagerTest, TestRemovedMountCanBeRemounted) {
  const std::string root_path = "smb://server/share1";
  int32_t mount_id;

  AddMount(root_path, &mount_id);
  EXPECT_TRUE(mounts_->RemoveMount(mount_id));

  // Should be able to be remounted again.
  AddMount(root_path, &mount_id);
}

TEST_F(MountManagerTest, TestReturnsEmptyPasswordWithInvalidFd) {
  std::unique_ptr<password_provider::Password> password =
      GetPassword(base::ScopedFD());
  EXPECT_FALSE(password);
}

TEST_F(MountManagerTest, TestReturnsEmptyPasswordWithEmptyPassword) {
  base::ScopedFD password_fd =
      WritePasswordToFile(&temp_files_, "" /* password */);
  EXPECT_TRUE(password_fd.is_valid());

  // password_fd should be false since the password was empty.
  std::unique_ptr<password_provider::Password> password =
      GetPassword(password_fd);
  EXPECT_FALSE(password);
}

TEST_F(MountManagerTest, TestPasswordLengthHeaderLongerThanContent) {
  const std::string password = "a";
  const size_t password_length = 8;

  std::vector<uint8_t> password_data(sizeof(password_length) + password.size());

  std::memcpy(password_data.data(), &password_length, sizeof(password_length));
  std::memcpy(password_data.data() + sizeof(password_length), password.c_str(),
              password.size());

  base::ScopedFD password_fd = temp_files_.CreateTempFile(password_data);
  std::unique_ptr<password_provider::Password> password_ptr =
      GetPassword(password_fd);

  // password_ptr should be false since length header of password_data exceeds
  // the size of the password string.
  EXPECT_FALSE(password_ptr);
}

TEST_F(MountManagerTest, TestEmptyPasswordFile) {
  base::ScopedFD password_fd = temp_files_.CreateTempFile();

  std::unique_ptr<password_provider::Password> password_ptr =
      GetPassword(password_fd);

  // password_ptr should be false since empty_password has no data.
  EXPECT_FALSE(password_ptr);
}

TEST_F(MountManagerTest, TestGetPasswordGetsValidPassword) {
  const std::string password = "test123";
  base::ScopedFD password_fd = WritePasswordToFile(&temp_files_, password);
  EXPECT_TRUE(password_fd.is_valid());

  std::unique_ptr<password_provider::Password> password_ptr =
      GetPassword(password_fd);
  EXPECT_TRUE(password_ptr);

  EXPECT_EQ(password_ptr->size(), password.size());
  EXPECT_EQ(std::string(password_ptr->GetRaw()), password);
}

TEST_F(MountManagerTest, TestBufferNullTerminatedWhenLengthTooSmall) {
  int32_t mount_id;

  SmbCredential credential = CreateCredential(kWorkgroup, kUsername, kPassword);

  AddMount(kMountRoot, std::move(credential), &mount_id);
  EXPECT_EQ(1, mounts_->MountCount());

  // Initialize buffers with 1.
  char workgroup_buffer[kBufferSize] = {1};
  char username_buffer[kBufferSize] = {1};
  char password_buffer[kBufferSize] = {1};

  SambaInterface* samba_interface = nullptr;
  EXPECT_TRUE(mounts_->GetSambaInterface(mount_id, &samba_interface));

  // Call the authentication function while passing 1 as the buffer sizes. This
  // should return false since the buffer sizes are too small.
  EXPECT_FALSE(mounts_->GetAuthentication(
      samba_interface->GetSambaInterfaceId(), kMountRoot, workgroup_buffer,
      1 /* workgroup_length */, username_buffer, 1 /* username_length */,
      password_buffer, 1 /* password_length */));

  // Buffers should be null-terminated.
  EXPECT_EQ('\0', workgroup_buffer[0]);
  EXPECT_EQ('\0', username_buffer[0]);
  EXPECT_EQ('\0', password_buffer[0]);

  EXPECT_TRUE(mounts_->RemoveMount(mount_id));
}

TEST_F(MountManagerTest, TestBufferNullTerminatedWhenNoCredsFound) {
  // Initialize buffers with 1.
  char workgroup_buffer[kBufferSize] = {1};
  char username_buffer[kBufferSize] = {1};
  char password_buffer[kBufferSize] = {1};

  // This should return false when no credential are found.
  EXPECT_FALSE(mounts_->GetAuthentication(
      -2 /* non-existing samba_interface_id */, kMountRoot, workgroup_buffer,
      kBufferSize, username_buffer, kBufferSize, password_buffer, kBufferSize));

  // Buffers should be null-terminated.
  EXPECT_EQ('\0', workgroup_buffer[0]);
  EXPECT_EQ('\0', username_buffer[0]);
  EXPECT_EQ('\0', password_buffer[0]);
}

TEST_F(MountManagerTest, TestAddingRemovingMultipleCredentials) {
  const std::string mount_root2 = "smb://192.168.0.1/share";
  const std::string workgroup2 = "workgroup2";
  const std::string username2 = "user2";
  const std::string password2 = "root";
  int32_t mount_id1;
  int32_t mount_id2;

  SmbCredential credential = CreateCredential(kWorkgroup, kUsername, kPassword);

  SmbCredential credential2 =
      CreateCredential(workgroup2, username2, password2);

  AddMount(kMountRoot, std::move(credential), &mount_id1);
  AddMount(mount_root2, std::move(credential2), &mount_id2);

  EXPECT_EQ(2, mounts_->MountCount());

  ExpectCredentialsEqual(mount_id1, kMountRoot, kWorkgroup, kUsername,
                         kPassword);

  ExpectCredentialsEqual(mount_id2, mount_root2, workgroup2, username2,
                         password2);

  EXPECT_TRUE(mounts_->RemoveMount(mount_id1));
  EXPECT_TRUE(mounts_->RemoveMount(mount_id2));
}

TEST_F(MountManagerTest, TestRemoveCredentialFromMultiple) {
  const std::string mount_root2 = "smb://192.168.0.1/share";
  const std::string workgroup2 = "workgroup2";
  const std::string username2 = "user2";
  const std::string password2 = "root";
  int32_t mount_id1;
  int32_t mount_id2;

  SmbCredential credential = CreateCredential(kWorkgroup, kUsername, kPassword);

  SmbCredential credential2 =
      CreateCredential(workgroup2, username2, password2);

  AddMount(kMountRoot, std::move(credential), &mount_id1);
  AddMount(mount_root2, std::move(credential2), &mount_id2);
  EXPECT_EQ(2, mounts_->MountCount());

  EXPECT_TRUE(mounts_->RemoveMount(mount_id1));

  EXPECT_EQ(1, mounts_->MountCount());

  ExpectCredentialsEqual(mount_id2, mount_root2, workgroup2, username2,
                         password2);

  EXPECT_TRUE(mounts_->RemoveMount(mount_id2));
  EXPECT_EQ(0, mounts_->MountCount());
}

TEST_F(MountManagerTest, TestEnableNTLM) {
  EXPECT_FALSE(enable_ntlm_);

  int mount_id;
  SmbCredential credential = CreateCredential(kWorkgroup, kUsername, kPassword);

  MountConfig mount_config(true /* enable_ntlm */);

  AddMountWithMountConfig(kMountRoot, std::move(credential), mount_config,
                          &mount_id);
  EXPECT_TRUE(enable_ntlm_);
}

TEST_F(MountManagerTest, TestDisableNTLM) {
  EXPECT_FALSE(enable_ntlm_);

  int mount_id;
  SmbCredential credential = CreateCredential(kWorkgroup, kUsername, kPassword);

  MountConfig mount_config(false /* enable_ntlm */);

  AddMountWithMountConfig(kMountRoot, std::move(credential), mount_config,
                          &mount_id);
  EXPECT_FALSE(enable_ntlm_);
}

TEST_F(MountManagerTest, TestUpdateMountCredentials) {
  int mount_id = 1;
  SmbCredential credential = CreateCredential(kWorkgroup, kUsername, kPassword);

  AddMount(kMountRoot, std::move(credential), &mount_id);
  EXPECT_EQ(1, mounts_->MountCount());

  ExpectCredentialsEqual(mount_id, kMountRoot, kWorkgroup, kUsername,
                         kPassword);

  const std::string workgroup2 = "updated_workgroup";
  const std::string username2 = "updated_user";
  const std::string password2 = "updated_password";

  SmbCredential credential2 =
      CreateCredential(workgroup2, username2, password2);

  EXPECT_TRUE(mounts_->UpdateMountCredential(mount_id, std::move(credential2)));

  ExpectCredentialsEqual(mount_id, kMountRoot, workgroup2, username2,
                         password2);
}

TEST_F(MountManagerTest, TestUpdateMountCredentialsOnNonExistentMount) {
  int mount_id = 999;
  const std::string workgroup2 = "updated_workgroup";
  const std::string username2 = "updated_user";
  const std::string password2 = "updated_password";
  SmbCredential credential2 =
      CreateCredential(workgroup2, username2, password2);

  EXPECT_EQ(0, mounts_->MountCount());
  EXPECT_FALSE(
      mounts_->UpdateMountCredential(mount_id, std::move(credential2)));
}

TEST_F(MountManagerTest, TestUpdateMountCredentialsOnUnmountedMount) {
  int mount_id = 1;
  SmbCredential credential = CreateCredential(kWorkgroup, kUsername, kPassword);

  AddMount(kMountRoot, std::move(credential), &mount_id);
  EXPECT_EQ(1, mounts_->MountCount());

  mounts_->RemoveMount(mount_id);

  EXPECT_EQ(0, mounts_->MountCount());

  const std::string workgroup2 = "updated_workgroup";
  const std::string username2 = "updated_user";
  const std::string password2 = "updated_password";

  SmbCredential credential2 =
      CreateCredential(workgroup2, username2, password2);

  EXPECT_FALSE(
      mounts_->UpdateMountCredential(mount_id, std::move(credential2)));
}

TEST_F(MountManagerTest, TestUpdateSharePathSucceeds) {
  int mount_id;

  EXPECT_EQ(0, mounts_->MountCount());
  AddMount(kMountRoot, &mount_id);

  const std::string new_path = "smb://192.168.50.105/testshare";
  EXPECT_TRUE(mounts_->UpdateSharePath(mount_id, new_path));

  std::string updated_path;
  EXPECT_TRUE(GetRootPath(mount_id, &updated_path));
  EXPECT_EQ(new_path, updated_path);
}

TEST_F(MountManagerTest, TestUpdateSharePathDoesNotAddANewMount) {
  int mount_id;

  EXPECT_EQ(0, mounts_->MountCount());
  AddMount(kMountRoot, &mount_id);
  EXPECT_EQ(1, mounts_->MountCount());

  const std::string new_path = "smb://192.168.50.105/testshare";
  EXPECT_TRUE(mounts_->UpdateSharePath(mount_id, new_path));

  EXPECT_EQ(1, mounts_->MountCount());
}

TEST_F(MountManagerTest, TestUpdateShareFailsOnNonExistentMount) {
  EXPECT_EQ(0, mounts_->MountCount());

  const std::string new_path = "smb://192.168.50.105/testshare";
  EXPECT_FALSE(mounts_->UpdateSharePath(999 /* mount_id */, new_path));
}

TEST_F(MountManagerTest, TestSavePassword) {
  base::FilePath password_file_path;
  ASSERT_TRUE(base::CreateTemporaryFileInDir(temp_files_.GetTempDirectoryPath(),
                                             &password_file_path));

  SmbCredential credential =
      CreateCredential(kWorkgroup, kUsername, kPassword, password_file_path);
  int32_t mount_id;
  AddMount(kMountRoot, std::move(credential), &mount_id);
  EXPECT_TRUE(mounts_->SavePasswordToFile(mount_id));

  base::File password_file(password_file_path,
                           base::File::FLAG_OPEN | base::File::FLAG_READ);
  ASSERT_TRUE(password_file.IsValid());
  base::ScopedFD password_fd(password_file.TakePlatformFile());
  std::unique_ptr<password_provider::Password> password_ptr =
      GetPassword(password_fd);
  EXPECT_TRUE(password_ptr);

  EXPECT_EQ(password_ptr->size(), strlen(kPassword));
  EXPECT_EQ(std::string(password_ptr->GetRaw()), kPassword);
}

TEST_F(MountManagerTest, TestSavePasswordInvalidMountId) {
  base::ScopedFD password_fd = temp_files_.CreateTempFile();
  ASSERT_TRUE(password_fd.is_valid());
  EXPECT_FALSE(mounts_->SavePasswordToFile(314159));
}

TEST_F(MountManagerTest, TestErasePasswordFile) {
  base::FilePath password_file_path;
  ASSERT_TRUE(base::CreateTemporaryFileInDir(temp_files_.GetTempDirectoryPath(),
                                             &password_file_path));

  SmbCredential credential =
      CreateCredential(kWorkgroup, kUsername, kPassword, password_file_path);
  int32_t mount_id;
  AddMount(kMountRoot, std::move(credential), &mount_id);
  EXPECT_TRUE(base::PathExists(password_file_path));
  EXPECT_TRUE(mounts_->ErasePasswordFile(mount_id));
  EXPECT_FALSE(base::PathExists(password_file_path));
}

TEST_F(MountManagerTest, TestEraseNonExistentPasswordFile) {
  base::FilePath password_file_path =
      temp_files_.GetTempDirectoryPath().Append("non-existent-password-file");
  ASSERT_FALSE(base::PathExists(password_file_path));

  SmbCredential credential =
      CreateCredential(kWorkgroup, kUsername, kPassword, password_file_path);
  int32_t mount_id;
  AddMount(kMountRoot, std::move(credential), &mount_id);
  EXPECT_TRUE(mounts_->ErasePasswordFile(mount_id));
}

}  // namespace smbprovider
