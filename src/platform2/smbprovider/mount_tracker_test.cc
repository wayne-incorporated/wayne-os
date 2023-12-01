// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <memory>

#include <base/functional/bind.h>
#include <base/test/simple_test_tick_clock.h>
#include <gtest/gtest.h>

#include "smbprovider/fake_samba_interface.h"
#include "smbprovider/fake_samba_proxy.h"
#include "smbprovider/mount_manager.h"
#include "smbprovider/mount_tracker.h"
#include "smbprovider/samba_interface.h"
#include "smbprovider/smb_credential.h"
#include "smbprovider/smbprovider_test_helper.h"
#include "smbprovider/temp_file_manager.h"

namespace smbprovider {

namespace {

std::unique_ptr<SambaInterface> SambaInterfaceFactoryFunction(
    FakeSambaInterface* fake_samba) {
  return std::make_unique<FakeSambaProxy>(fake_samba);
}

}  // namespace

constexpr char kMountRoot[] = "smb://192.168.0.1/test";
constexpr char kWorkgroup[] = "domain";
constexpr char kUsername[] = "user1";
constexpr char kPassword[] = "admin";

class MountTrackerTest : public testing::Test {
 public:
  using SambaInterfaceFactory =
      base::RepeatingCallback<std::unique_ptr<SambaInterface>()>;

  MountTrackerTest() {
    auto tick_clock = std::make_unique<base::SimpleTestTickClock>();

    auto fake_samba_ = std::make_unique<FakeSambaInterface>();
    samba_interface_factory_ =
        base::BindRepeating(&SambaInterfaceFactoryFunction, fake_samba_.get());

    mount_tracker_ = std::make_unique<MountTracker>(
        std::move(tick_clock), false /* metadata_cache_enabled */);
  }
  MountTrackerTest(const MountTrackerTest&) = delete;
  MountTrackerTest& operator=(const MountTrackerTest&) = delete;

  ~MountTrackerTest() override = default;

 protected:
  void AddMountWithEmptyCredential(const std::string& root_path,
                                   int32_t* mount_id) {
    SmbCredential credential("" /* workgroup */, "" /* username */,
                             GetEmptyPassword());

    mount_tracker_->AddMount(root_path, std::move(credential),
                             CreateSambaInterface(), mount_id);
  }

  void AddMount(const std::string& root_path,
                const std::string& workgroup,
                const std::string& username,
                const std::string& password,
                int32_t* mount_id) {
    SmbCredential credential(workgroup, username, CreatePassword(password));

    mount_tracker_->AddMount(root_path, std::move(credential),
                             CreateSambaInterface(), mount_id);
  }

  std::unique_ptr<SambaInterface> CreateSambaInterface() {
    return samba_interface_factory_.Run();
  }

  void ExpectCredentialsEqual(int32_t mount_id,
                              const std::string& workgroup,
                              const std::string& username,
                              const std::string& password) {
    const SambaInterface::SambaInterfaceId samba_interface_id =
        GetSambaInterfaceId(mount_id);

    const SmbCredential& cred =
        mount_tracker_->GetCredential(samba_interface_id);

    EXPECT_EQ(workgroup, std::string(cred.workgroup));
    EXPECT_EQ(username, std::string(cred.username));

    if (!password.empty()) {
      EXPECT_EQ(password, std::string(cred.password->GetRaw()));
    } else {
      // Password is empty but check if credential-stored password is empty too.
      EXPECT_TRUE(cred.password.get() == nullptr);
    }
  }

  SambaInterface::SambaInterfaceId GetSambaInterfaceId(const int32_t mount_id) {
    SambaInterface* samba_interface;
    EXPECT_TRUE(mount_tracker_->GetSambaInterface(mount_id, &samba_interface));

    return samba_interface->GetSambaInterfaceId();
  }

  std::unique_ptr<password_provider::Password> CreatePassword(
      const std::string& password) {
    return GetPassword(WritePasswordToFile(password));
  }

  std::string GetSharePath(int32_t mount_id) const {
    std::string path;
    if (!mount_tracker_->GetMountRootPath(mount_id, &path)) {
      return {};
    }
    return path;
  }

  std::unique_ptr<MountTracker> mount_tracker_;
  TempFileManager temp_files_;
  SambaInterfaceFactory samba_interface_factory_;

 private:
  base::ScopedFD WriteEmptyPasswordToFile() {
    return smbprovider::WritePasswordToFile(&temp_files_, "" /* password */);
  }

  base::ScopedFD WritePasswordToFile(const std::string& password) {
    return smbprovider::WritePasswordToFile(&temp_files_, password);
  }

  std::unique_ptr<password_provider::Password> GetEmptyPassword() {
    return GetPassword(WriteEmptyPasswordToFile());
  }
};

TEST_F(MountTrackerTest, TestNegativeMounts) {
  const std::string root_path = "smb://server/share";
  const int32_t mount_id = 1;

  EXPECT_EQ(GetSharePath(mount_id), "");
  EXPECT_FALSE(mount_tracker_->IsAlreadyMounted(mount_id));
}

TEST_F(MountTrackerTest, TestAddMount) {
  const std::string root_path = "smb://server/share";

  int32_t mount_id;
  AddMountWithEmptyCredential(root_path, &mount_id);

  EXPECT_EQ(1, mount_tracker_->MountCount());

  EXPECT_EQ(GetSharePath(mount_id), root_path);
  EXPECT_TRUE(mount_tracker_->IsAlreadyMounted(mount_id));
}

TEST_F(MountTrackerTest, TestAddSameMount) {
  const std::string root_path = "smb://server/share";

  int32_t mount_id;
  AddMountWithEmptyCredential(root_path, &mount_id);

  EXPECT_EQ(GetSharePath(mount_id), root_path);
  EXPECT_TRUE(mount_tracker_->IsAlreadyMounted(mount_id));
  EXPECT_EQ(1, mount_tracker_->MountCount());

  int32_t mount_id2;
  AddMountWithEmptyCredential(root_path, &mount_id2);

  EXPECT_EQ(GetSharePath(mount_id2), root_path);
  EXPECT_TRUE(mount_tracker_->IsAlreadyMounted(mount_id));
  EXPECT_TRUE(mount_tracker_->IsAlreadyMounted(mount_id2));

  EXPECT_EQ(2, mount_tracker_->MountCount());
  EXPECT_NE(mount_id, mount_id2);
}

TEST_F(MountTrackerTest, TestMountCount) {
  const std::string root_path = "smb://server/share1";
  const std::string root_path2 = "smb://server/share2";

  EXPECT_EQ(0, mount_tracker_->MountCount());

  int32_t mount_id1;
  AddMountWithEmptyCredential(root_path, &mount_id1);

  EXPECT_EQ(1, mount_tracker_->MountCount());

  int32_t mount_id2;
  AddMountWithEmptyCredential(root_path2, &mount_id2);

  EXPECT_EQ(2, mount_tracker_->MountCount());
  EXPECT_NE(mount_id1, mount_id2);
}

TEST_F(MountTrackerTest, TestAddMultipleDifferentMountId) {
  const std::string root_path1 = "smb://server/share1";
  int32_t mount_id1;
  AddMountWithEmptyCredential(root_path1, &mount_id1);

  const std::string root_path2 = "smb://server/share2";
  int32_t mount_id2;
  AddMountWithEmptyCredential(root_path2, &mount_id2);

  EXPECT_GE(mount_id1, 0);
  EXPECT_GE(mount_id2, 0);
  EXPECT_NE(mount_id1, mount_id2);
}

TEST_F(MountTrackerTest, TestAddRemoveMount) {
  // Add a new mount.
  const std::string root_path = "smb://server/share";
  int32_t mount_id;

  AddMountWithEmptyCredential(root_path, &mount_id);

  EXPECT_EQ(1, mount_tracker_->MountCount());
  EXPECT_EQ(GetSharePath(mount_id), root_path);

  // Verify the mount can be removed.
  EXPECT_TRUE(mount_tracker_->RemoveMount(mount_id));
  EXPECT_EQ(0, mount_tracker_->MountCount());

  EXPECT_EQ(GetSharePath(mount_id), "");
  EXPECT_FALSE(mount_tracker_->IsAlreadyMounted(mount_id));
}

TEST_F(MountTrackerTest, TestAddThenRemoveWrongMount) {
  // Add a new mount.
  const std::string root_path = "smb://server/share";
  int32_t mount_id;

  AddMountWithEmptyCredential(root_path, &mount_id);

  // Verify RemoveMount fails with an invalid id and nothing is removed.
  const int32_t invalid_mount_id = mount_id + 1;
  EXPECT_FALSE(mount_tracker_->IsAlreadyMounted(invalid_mount_id));

  EXPECT_FALSE(mount_tracker_->RemoveMount(invalid_mount_id));

  EXPECT_EQ(1, mount_tracker_->MountCount());

  EXPECT_TRUE(mount_tracker_->IsAlreadyMounted(mount_id));
  EXPECT_EQ(GetSharePath(mount_id), root_path);

  // Verify the valid id can still be removed.
  EXPECT_TRUE(mount_tracker_->RemoveMount(mount_id));

  EXPECT_EQ(0, mount_tracker_->MountCount());

  EXPECT_FALSE(mount_tracker_->IsAlreadyMounted(mount_id));
  EXPECT_EQ(GetSharePath(mount_id), "");
}

TEST_F(MountTrackerTest, TestAddRemoveMultipleMounts) {
  const std::string root_path1 = "smb://server/share1";
  const std::string root_path2 = "smb://server/share2";

  // Add two mounts and verify they were both added.
  int32_t mount_id_1;
  int32_t mount_id_2;

  AddMountWithEmptyCredential(root_path1, &mount_id_1);
  AddMountWithEmptyCredential(root_path2, &mount_id_2);

  EXPECT_EQ(2, mount_tracker_->MountCount());

  // Remove the second id, verify it is removed, and the first remains.
  EXPECT_TRUE(mount_tracker_->RemoveMount(mount_id_2));

  EXPECT_EQ(1, mount_tracker_->MountCount());

  EXPECT_FALSE(mount_tracker_->IsAlreadyMounted(mount_id_2));
  EXPECT_EQ(GetSharePath(mount_id_2), "");

  EXPECT_TRUE(mount_tracker_->IsAlreadyMounted(mount_id_1));
  EXPECT_EQ(GetSharePath(mount_id_1), root_path1);

  // Remove the first id and verify it is also removed.
  EXPECT_TRUE(mount_tracker_->RemoveMount(mount_id_1));

  EXPECT_EQ(0, mount_tracker_->MountCount());

  EXPECT_FALSE(mount_tracker_->IsAlreadyMounted(mount_id_1));
  EXPECT_EQ(GetSharePath(mount_id_1), "");
}

TEST_F(MountTrackerTest, TestRemovedMountCanBeRemounted) {
  const std::string root_path = "smb://server/share1";

  int32_t mount_id;
  AddMountWithEmptyCredential(root_path, &mount_id);

  EXPECT_TRUE(mount_tracker_->RemoveMount(mount_id));

  EXPECT_EQ(0, mount_tracker_->MountCount());

  // Should be able to be remounted again.
  AddMountWithEmptyCredential(root_path, &mount_id);

  EXPECT_EQ(1, mount_tracker_->MountCount());
}

TEST_F(MountTrackerTest, TestRemoveInvalidMountId) {
  const int32_t mount_id = 5;

  EXPECT_FALSE(mount_tracker_->RemoveMount(mount_id));

  // Ensure AddMount still works.
  const std::string root_path = "smb://server/share";

  int32_t mount_id1;
  AddMountWithEmptyCredential(root_path, &mount_id1);

  EXPECT_EQ(1, mount_tracker_->MountCount());

  // Ensure RemoveMount still works.
  EXPECT_TRUE(mount_tracker_->RemoveMount(mount_id1));

  EXPECT_EQ(0, mount_tracker_->MountCount());
}

TEST_F(MountTrackerTest, TestGetFullPath) {
  // Add a new mount.
  const std::string root_path = "smb://server/share";
  int32_t mount_id;

  AddMountWithEmptyCredential(root_path, &mount_id);

  // Verify the full path is as expected.
  const std::string entry_path = "/foo/bar";
  const std::string expected_full_path = root_path + entry_path;

  std::string actual_full_path;
  EXPECT_TRUE(
      mount_tracker_->GetFullPath(mount_id, entry_path, &actual_full_path));

  EXPECT_EQ(expected_full_path, actual_full_path);
}

TEST_F(MountTrackerTest, TestGetFullPathWithInvalidId) {
  // Add a new mount.
  const std::string root_path = "smb://server/share";
  int32_t mount_id;

  AddMountWithEmptyCredential(root_path, &mount_id);

  // Verify calling GetFullPath() with an invalid id fails.
  const int32_t invalid_mount_id = mount_id + 1;

  EXPECT_FALSE(mount_tracker_->IsAlreadyMounted(invalid_mount_id));
  std::string full_path;
  EXPECT_FALSE(
      mount_tracker_->GetFullPath(invalid_mount_id, "/foo/bar", &full_path));
}

TEST_F(MountTrackerTest, TestGetFullPathMultipleMounts) {
  // Add two mounts with different roots.
  const std::string root_path_1 = "smb://server/share1";
  const std::string root_path_2 = "smb://server/share2";

  ASSERT_NE(root_path_1, root_path_2);

  int32_t mount_id_1;
  int32_t mount_id_2;

  AddMountWithEmptyCredential(root_path_1, &mount_id_1);
  AddMountWithEmptyCredential(root_path_2, &mount_id_2);

  // Verify correct ids map to the correct paths.
  std::string actual_full_path;
  const std::string entry_path = "/foo/bar";
  const std::string expected_full_path_1 = root_path_1 + entry_path;
  const std::string expected_full_path_2 = root_path_2 + entry_path;

  EXPECT_TRUE(
      mount_tracker_->GetFullPath(mount_id_1, entry_path, &actual_full_path));

  EXPECT_EQ(expected_full_path_1, actual_full_path);

  EXPECT_TRUE(
      mount_tracker_->GetFullPath(mount_id_2, entry_path, &actual_full_path));

  EXPECT_EQ(expected_full_path_2, actual_full_path);
}

TEST_F(MountTrackerTest, TestGetRelativePath) {
  const std::string root_path = "smb://server/share1";
  const std::string expected_relative_path = "/animals/dog.jpg";
  const std::string full_path = root_path + expected_relative_path;

  int32_t mount_id;
  AddMountWithEmptyCredential(root_path, &mount_id);

  EXPECT_EQ(expected_relative_path,
            mount_tracker_->GetRelativePath(mount_id, full_path));
}

TEST_F(MountTrackerTest, TestGetRelativePathOnRoot) {
  const std::string root_path = "smb://server/share1";
  const std::string expected_relative_path = "/";
  const std::string full_path = root_path + expected_relative_path;

  int32_t mount_id;
  AddMountWithEmptyCredential(root_path, &mount_id);

  EXPECT_EQ(expected_relative_path,
            mount_tracker_->GetRelativePath(mount_id, full_path));
}

TEST_F(MountTrackerTest, TestGetEmptyCredential) {
  const std::string root_path = "smb://server/share";

  int32_t mount_id;
  AddMountWithEmptyCredential(root_path, &mount_id);

  EXPECT_EQ(1, mount_tracker_->MountCount());
  EXPECT_TRUE(mount_tracker_->IsAlreadyMounted(mount_id));

  ExpectCredentialsEqual(mount_id, "" /* Workgroup */, "" /* Username */,
                         "" /* Password */);
}

TEST_F(MountTrackerTest, TestAddMountWithGetCredential) {
  int32_t mount_id;
  AddMount(kMountRoot, kWorkgroup, kUsername, kPassword, &mount_id);

  EXPECT_EQ(1, mount_tracker_->MountCount());
  EXPECT_TRUE(mount_tracker_->IsAlreadyMounted(mount_id));

  ExpectCredentialsEqual(mount_id, kWorkgroup, kUsername, kPassword);
}

TEST_F(MountTrackerTest, TestAddMountWithEmptyPassword) {
  const std::string password = "";

  int32_t mount_id;
  AddMount(kMountRoot, kWorkgroup, kUsername, password, &mount_id);

  EXPECT_GE(mount_id, 0);
  EXPECT_EQ(1, mount_tracker_->MountCount());
  EXPECT_TRUE(mount_tracker_->IsAlreadyMounted(mount_id));

  ExpectCredentialsEqual(mount_id, kWorkgroup, kUsername, password);
}

TEST_F(MountTrackerTest, TestAddingRemovingMultipleCredentials) {
  const std::string mount_root2 = "smb://192.168.0.1/share";
  const std::string workgroup2 = "workgroup2";
  const std::string username2 = "user2";
  const std::string password2 = "root";

  int32_t mount_id1;
  AddMount(kMountRoot, kWorkgroup, kUsername, kPassword, &mount_id1);

  int32_t mount_id2;
  AddMount(mount_root2, workgroup2, username2, password2, &mount_id2);

  EXPECT_EQ(2, mount_tracker_->MountCount());

  EXPECT_EQ(GetSharePath(mount_id1), kMountRoot);
  EXPECT_EQ(GetSharePath(mount_id2), mount_root2);

  ExpectCredentialsEqual(mount_id1, kWorkgroup, kUsername, kPassword);

  ExpectCredentialsEqual(mount_id2, workgroup2, username2, password2);

  EXPECT_TRUE(mount_tracker_->RemoveMount(mount_id1));
  EXPECT_TRUE(mount_tracker_->RemoveMount(mount_id2));
}

TEST_F(MountTrackerTest, TestRemoveCredentialFromMultiple) {
  const std::string mount_root2 = "smb://192.168.0.1/share";
  const std::string workgroup2 = "workgroup2";
  const std::string username2 = "user2";
  const std::string password2 = "root";

  int32_t mount_id1;
  AddMount(kMountRoot, kWorkgroup, kUsername, kPassword, &mount_id1);

  int32_t mount_id2;
  AddMount(mount_root2, workgroup2, username2, password2, &mount_id2);

  EXPECT_EQ(2, mount_tracker_->MountCount());

  EXPECT_TRUE(mount_tracker_->RemoveMount(mount_id1));

  EXPECT_EQ(1, mount_tracker_->MountCount());
  EXPECT_EQ(GetSharePath(mount_id1), "");
  EXPECT_EQ(GetSharePath(mount_id2), mount_root2);

  ExpectCredentialsEqual(mount_id2, workgroup2, username2, password2);

  EXPECT_TRUE(mount_tracker_->RemoveMount(mount_id2));
  EXPECT_EQ(0, mount_tracker_->MountCount());
}

TEST_F(MountTrackerTest, TestIsSambaInterfaceIdMounted) {
  int32_t mount_id;
  AddMount(kMountRoot, kWorkgroup, kUsername, kPassword, &mount_id);

  EXPECT_EQ(1, mount_tracker_->MountCount());

  SambaInterface::SambaInterfaceId samba_interface_id =
      GetSambaInterfaceId(mount_id);

  EXPECT_TRUE(mount_tracker_->IsAlreadyMounted(samba_interface_id));
}

TEST_F(MountTrackerTest, TestAddRemoveSambaInterfaceId) {
  int32_t mount_id;
  AddMount(kMountRoot, kWorkgroup, kUsername, kPassword, &mount_id);

  EXPECT_EQ(1, mount_tracker_->MountCount());

  SambaInterface::SambaInterfaceId samba_interface_id =
      GetSambaInterfaceId(mount_id);

  EXPECT_TRUE(mount_tracker_->IsAlreadyMounted(samba_interface_id));

  EXPECT_TRUE(mount_tracker_->RemoveMount(mount_id));

  EXPECT_FALSE(mount_tracker_->IsAlreadyMounted(samba_interface_id));
}

TEST_F(MountTrackerTest, TestNonExistentSambaInterfaceId) {
  uintptr_t samba_interface_id = 1;
  SambaInterface::SambaInterfaceId non_existent_id =
      reinterpret_cast<SambaInterface::SambaInterfaceId>(samba_interface_id);

  EXPECT_FALSE(mount_tracker_->IsAlreadyMounted(non_existent_id));
}

TEST_F(MountTrackerTest, TestGetCacheNoMounts) {
  MetadataCache* cache = nullptr;

  EXPECT_FALSE(mount_tracker_->GetMetadataCache(0, &cache));
}

TEST_F(MountTrackerTest, TestGetCache) {
  int32_t mount_id;
  AddMountWithEmptyCredential("smb://server/share", &mount_id);

  MetadataCache* cache = nullptr;
  EXPECT_TRUE(mount_tracker_->GetMetadataCache(mount_id, &cache));
  EXPECT_NE(nullptr, cache);
}

TEST_F(MountTrackerTest, TestGetCacheForInvalidMount) {
  int32_t mount_id;
  AddMountWithEmptyCredential("smb://server/share", &mount_id);

  // mount_id + 1 does not exist.
  MetadataCache* cache = nullptr;
  EXPECT_FALSE(mount_tracker_->GetMetadataCache(mount_id + 1, &cache));
}

TEST_F(MountTrackerTest, TestUpdateMountCredentials) {
  int32_t mount_id;
  AddMount(kMountRoot, kWorkgroup, kUsername, kPassword, &mount_id);

  EXPECT_EQ(1, mount_tracker_->MountCount());
  EXPECT_TRUE(mount_tracker_->IsAlreadyMounted(mount_id));

  ExpectCredentialsEqual(mount_id, kWorkgroup, kUsername, kPassword);

  const std::string workgroup2 = "updated_workgroup";
  const std::string username2 = "updated_username";
  const std::string password2 = "updated_password";

  SmbCredential credential(workgroup2, username2, CreatePassword(password2));
  EXPECT_TRUE(
      mount_tracker_->UpdateCredential(mount_id, std::move(credential)));

  ExpectCredentialsEqual(mount_id, workgroup2, username2, password2);
}

TEST_F(MountTrackerTest, TestUpdateMountCredentialsOnNontExistentMountId) {
  int32_t mount_id = 999;

  const std::string workgroup2 = "updated_workgroup";
  const std::string username2 = "updated_username";
  const std::string password2 = "updated_password";

  SmbCredential credential(workgroup2, username2, CreatePassword(password2));

  EXPECT_EQ(0, mount_tracker_->MountCount());
  EXPECT_FALSE(
      mount_tracker_->UpdateCredential(mount_id, std::move(credential)));

  EXPECT_EQ(0, mount_tracker_->MountCount());
}

TEST_F(MountTrackerTest, TestUpdateSharePath) {
  int32_t mount_id;
  AddMount(kMountRoot, kWorkgroup, kUsername, kPassword, &mount_id);

  EXPECT_EQ(GetSharePath(mount_id), kMountRoot);

  const std::string updated_path = "smb://192.168.1.1/test";
  EXPECT_TRUE(mount_tracker_->UpdateSharePath(mount_id, updated_path));

  // Check that the share path was successfully updated.
  EXPECT_EQ(GetSharePath(mount_id), updated_path);
}

TEST_F(MountTrackerTest, TestUpdateSharePathDoesNotCreateNewMount) {
  int32_t mount_id;
  AddMount(kMountRoot, kWorkgroup, kUsername, kPassword, &mount_id);

  EXPECT_EQ(GetSharePath(mount_id), kMountRoot);

  const std::string updated_path = "smb://192.168.1.1/test";
  EXPECT_TRUE(mount_tracker_->UpdateSharePath(mount_id, updated_path));

  // Check that |updated_path| is stored.
  EXPECT_EQ(GetSharePath(mount_id), updated_path);

  EXPECT_EQ(1, mount_tracker_->MountCount());
}

TEST_F(MountTrackerTest, TestUpdateSharePathFailsOnNonExistingMount) {
  EXPECT_EQ(0, mount_tracker_->MountCount());

  const std::string updated_path = "smb://192.168.1.1/test";
  EXPECT_FALSE(
      mount_tracker_->UpdateSharePath(999 /* mount_id */, updated_path));
}

}  // namespace smbprovider
