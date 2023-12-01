// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/homedirs.h"

#include <optional>
#include <set>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <brillo/cryptohome.h>
#include <brillo/blkdev_utils/mock_lvm.h>
#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <policy/mock_device_policy.h>

#include "cryptohome/filesystem_layout.h"
#include "cryptohome/mock_keyset_management.h"
#include "cryptohome/mock_platform.h"
#include "cryptohome/storage/cryptohome_vault_factory.h"
#include "cryptohome/storage/encrypted_container/encrypted_container.h"
#include "cryptohome/storage/encrypted_container/encrypted_container_factory.h"
#include "cryptohome/storage/encrypted_container/fake_backing_device.h"
#include "cryptohome/storage/error.h"
#include "cryptohome/storage/error_test_helpers.h"
#include "cryptohome/storage/keyring/fake_keyring.h"
#include "cryptohome/storage/mount_constants.h"
#include "cryptohome/username.h"

using ::cryptohome::storage::testing::IsError;
using ::hwsec_foundation::error::testing::IsOk;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::NiceMock;
using ::testing::Return;

namespace cryptohome {
namespace {

struct UserPassword {
  const char* name;
  const char* password;
};

constexpr char kUser0[] = "First User";
constexpr char kUserPassword0[] = "user0_pass";
constexpr char kUser1[] = "Second User";
constexpr char kUserPassword1[] = "user1_pass";
constexpr char kUser2[] = "Third User";
constexpr char kUserPassword2[] = "user2_pass";
constexpr char kOwner[] = "I am the device owner";
constexpr char kOwnerPassword[] = "owner_pass";

constexpr int kOwnerIndex = 3;

ACTION_P2(SetOwner, owner_known, owner) {
  if (owner_known)
    *arg0 = owner;
  return owner_known;
}

ACTION_P(SetEphemeralSettings, ephemeral_settings) {
  *arg0 = ephemeral_settings;
  return true;
}

struct UserInfo {
  Username name;
  ObfuscatedUsername obfuscated;
  brillo::SecureBlob passkey;
  base::FilePath homedir_path;
  base::FilePath user_path;
};

struct test_homedir {
  const char* obfuscated;
  base::Time::Exploded time;
};

}  // namespace

class HomeDirsTest
    : public ::testing::TestWithParam<bool /* should_test_ecryptfs */> {
 public:
  HomeDirsTest() : mock_device_policy_(new policy::MockDevicePolicy()) {}
  ~HomeDirsTest() override {}

  // Not copyable or movable
  HomeDirsTest(const HomeDirsTest&) = delete;
  HomeDirsTest& operator=(const HomeDirsTest&) = delete;
  HomeDirsTest(HomeDirsTest&&) = delete;
  HomeDirsTest& operator=(HomeDirsTest&&) = delete;

  void SetUp() override {
    PreparePolicy(true, kOwner, "");

    std::unique_ptr<EncryptedContainerFactory> container_factory =
        std::make_unique<EncryptedContainerFactory>(
            &platform_, std::make_unique<FakeKeyring>(),
            std::make_unique<BackingDeviceFactory>(&platform_));
    vault_factory_ = std::make_unique<CryptohomeVaultFactory>(
        &platform_, std::move(container_factory));
    HomeDirs::RemoveCallback remove_callback =
        base::BindRepeating(&MockKeysetManagement::RemoveLECredentials,
                            base::Unretained(&keyset_management_));
    homedirs_ = std::make_unique<HomeDirs>(
        &platform_,
        std::make_unique<policy::PolicyProvider>(
            std::unique_ptr<policy::MockDevicePolicy>(mock_device_policy_)),
        remove_callback, vault_factory_.get());

    AddUser(kUser0, kUserPassword0);
    AddUser(kUser1, kUserPassword1);
    AddUser(kUser2, kUserPassword2);
    AddUser(kOwner, kOwnerPassword);

    ASSERT_EQ(kOwner, *users_[kOwnerIndex].name);

    PrepareDirectoryStructure();
  }

  void AddUser(const char* name, const char* password) {
    Username username(name);
    ObfuscatedUsername obfuscated =
        brillo::cryptohome::home::SanitizeUserName(username);
    brillo::SecureBlob passkey(password);

    UserInfo info = {username, obfuscated, passkey, UserPath(obfuscated),
                     brillo::cryptohome::home::GetHashedUserPath(obfuscated)};
    users_.push_back(info);
  }

  void PreparePolicy(bool owner_known,
                     const std::string& owner,
                     const std::string& clean_up_strategy) {
    EXPECT_CALL(*mock_device_policy_,
                LoadPolicy(/*delete_invalid_files=*/false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_device_policy_, GetOwner(_))
        .WillRepeatedly(SetOwner(owner_known, owner));
  }

  // Returns true if the test is running for eCryptfs, false if for dircrypto.
  bool ShouldTestEcryptfs() const { return GetParam(); }

 protected:
  NiceMock<MockPlatform> platform_;
  MockKeysetManagement keyset_management_;
  policy::MockDevicePolicy* mock_device_policy_;  // owned by homedirs_
  std::unique_ptr<CryptohomeVaultFactory> vault_factory_;
  std::unique_ptr<HomeDirs> homedirs_;

  // Information about users' homedirs. The order of users is equal to kUsers.
  std::vector<UserInfo> users_;

  static const uid_t kAndroidSystemRealUid =
      HomeDirs::kAndroidSystemUid + kArcContainerShiftUid;

  void PrepareDirectoryStructure() {
    ASSERT_TRUE(platform_.CreateDirectory(
        brillo::cryptohome::home::GetUserPathPrefix()));
    for (const auto& user : users_) {
      ASSERT_TRUE(platform_.CreateDirectory(user.homedir_path));
      ASSERT_TRUE(
          platform_.CreateDirectory(user.homedir_path.Append(kMountDir)));
      if (ShouldTestEcryptfs()) {
        ASSERT_TRUE(platform_.CreateDirectory(
            user.homedir_path.Append(kEcryptfsVaultDir)));
      }
      ASSERT_TRUE(platform_.CreateDirectory(user.user_path));
    }
  }
};

INSTANTIATE_TEST_SUITE_P(WithEcryptfs, HomeDirsTest, ::testing::Values(true));
INSTANTIATE_TEST_SUITE_P(WithDircrypto, HomeDirsTest, ::testing::Values(false));

TEST_P(HomeDirsTest, RemoveEphemeralCryptohomes_Error) {
  EXPECT_TRUE(platform_.DirectoryExists(users_[0].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[1].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[2].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[kOwnerIndex].homedir_path));

  EXPECT_CALL(platform_, IsDirectoryMounted(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(keyset_management_, RemoveLECredentials(_)).Times(0);
  EXPECT_CALL(*mock_device_policy_, GetEphemeralSettings(_))
      .WillRepeatedly(Return(false));

  auto result = homedirs_->RemoveCryptohomesBasedOnPolicy();
  EXPECT_EQ(result, HomeDirs::CryptohomesRemovedStatus::kError);

  EXPECT_TRUE(platform_.DirectoryExists(users_[0].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[1].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[2].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[kOwnerIndex].homedir_path));
}

// When the global ephemeral user policy is not set, and there are no ephemeral
// or non-ephemeral users, we should not remove cryptohomes.
TEST_P(HomeDirsTest, RemoveEphemeralCryptohomes_EphemeralUsersDisabled) {
  EXPECT_TRUE(platform_.DirectoryExists(users_[0].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[1].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[2].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[kOwnerIndex].homedir_path));

  EXPECT_CALL(platform_, IsDirectoryMounted(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(keyset_management_, RemoveLECredentials(_)).Times(0);
  policy::DevicePolicy::EphemeralSettings ephemeral_settings;
  ephemeral_settings.global_ephemeral_users_enabled = false;
  EXPECT_CALL(*mock_device_policy_, GetEphemeralSettings(_))
      .WillRepeatedly(SetEphemeralSettings(ephemeral_settings));

  auto result = homedirs_->RemoveCryptohomesBasedOnPolicy();
  EXPECT_EQ(result, HomeDirs::CryptohomesRemovedStatus::kNone);

  EXPECT_TRUE(platform_.DirectoryExists(users_[0].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[1].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[2].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[kOwnerIndex].homedir_path));
}

// When the global ephemeral user policy is set, and there are no ephemeral
// or non-ephemeral users and the device is enterprise owned we should remove
// all cryptohomes except the owner.
TEST_P(HomeDirsTest, RemoveEphemeralCryptohomes_EphemeralUsersEnabled) {
  EXPECT_TRUE(platform_.DirectoryExists(users_[0].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[1].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[2].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[kOwnerIndex].homedir_path));

  EXPECT_CALL(platform_, IsDirectoryMounted(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(keyset_management_, RemoveLECredentials(_)).Times(3);
  policy::DevicePolicy::EphemeralSettings ephemeral_settings;
  ephemeral_settings.global_ephemeral_users_enabled = true;
  EXPECT_CALL(*mock_device_policy_, GetEphemeralSettings(_))
      .WillRepeatedly(SetEphemeralSettings(ephemeral_settings));

  auto result = homedirs_->RemoveCryptohomesBasedOnPolicy();
  EXPECT_EQ(result, HomeDirs::CryptohomesRemovedStatus::kSome);

  // Non-owners' vaults are removed.
  EXPECT_FALSE(platform_.DirectoryExists(users_[0].homedir_path));
  EXPECT_FALSE(platform_.DirectoryExists(users_[1].homedir_path));
  EXPECT_FALSE(platform_.DirectoryExists(users_[2].homedir_path));

  // Owner's vault still exists.
  EXPECT_TRUE(platform_.DirectoryExists(users_[kOwnerIndex].homedir_path));
}

// When the global ephemeral user policy is set, and there are no ephemeral
// or non-ephemeral users and the device is not enterprise owned we should
// remove all cryptohomes.
TEST_P(HomeDirsTest,
       RemoveEphemeralCryptohomes_EphemeralUsersEnabled_EnterpriseOwned) {
  EXPECT_TRUE(platform_.DirectoryExists(users_[0].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[1].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[2].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[kOwnerIndex].homedir_path));

  EXPECT_CALL(platform_, IsDirectoryMounted(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(keyset_management_, RemoveLECredentials(_)).Times(4);
  policy::DevicePolicy::EphemeralSettings ephemeral_settings;
  ephemeral_settings.global_ephemeral_users_enabled = true;
  EXPECT_CALL(*mock_device_policy_, GetEphemeralSettings(_))
      .WillRepeatedly(SetEphemeralSettings(ephemeral_settings));

  homedirs_->set_enterprise_owned(true);
  auto result = homedirs_->RemoveCryptohomesBasedOnPolicy();
  EXPECT_EQ(result, HomeDirs::CryptohomesRemovedStatus::kAll);

  // When enterprise owned there is no owner vault.
  EXPECT_FALSE(platform_.DirectoryExists(users_[0].homedir_path));
  EXPECT_FALSE(platform_.DirectoryExists(users_[1].homedir_path));
  EXPECT_FALSE(platform_.DirectoryExists(users_[2].homedir_path));
  EXPECT_FALSE(platform_.DirectoryExists(users_[kOwnerIndex].homedir_path));
}

// When the global ephemeral user policy is set, and there are ephemeral
// and non-ephemeral users, we should remove all cryptohomes except the owner
// and the non-ephemeral cryptohomes.
TEST_P(HomeDirsTest,
       RemoveEphemeralCryptohomes_EphemeralUsersEnabled_WithAllowLists) {
  EXPECT_TRUE(platform_.DirectoryExists(users_[0].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[1].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[2].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[kOwnerIndex].homedir_path));

  EXPECT_CALL(platform_, IsDirectoryMounted(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(keyset_management_, RemoveLECredentials(_)).Times(2);
  policy::DevicePolicy::EphemeralSettings ephemeral_settings;
  ephemeral_settings.global_ephemeral_users_enabled = true;
  ephemeral_settings.specific_ephemeral_users.push_back(kUser0);
  ephemeral_settings.specific_nonephemeral_users.push_back(kUser1);
  EXPECT_CALL(*mock_device_policy_, GetEphemeralSettings(_))
      .WillRepeatedly(SetEphemeralSettings(ephemeral_settings));

  auto result = homedirs_->RemoveCryptohomesBasedOnPolicy();
  EXPECT_EQ(result, HomeDirs::CryptohomesRemovedStatus::kSome);

  // Ephemeral vaults are removed.
  EXPECT_FALSE(platform_.DirectoryExists(users_[0].homedir_path));
  EXPECT_FALSE(platform_.DirectoryExists(users_[2].homedir_path));
  // Non-ephemeral cryptohome still exists.
  EXPECT_TRUE(platform_.DirectoryExists(users_[1].homedir_path));
  // Owner's vault still exists.
  EXPECT_TRUE(platform_.DirectoryExists(users_[kOwnerIndex].homedir_path));
}

// When the global ephemeral user policy is not set, and there are ephemeral
// and non-ephemeral users, we should remove only the ephemeral cryptohomes.
TEST_P(HomeDirsTest,
       RemoveEphemeralCryptohomes_EphemeralUsersDisabled_WithAllowLists) {
  EXPECT_TRUE(platform_.DirectoryExists(users_[0].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[1].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[2].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[kOwnerIndex].homedir_path));

  EXPECT_CALL(platform_, IsDirectoryMounted(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(keyset_management_, RemoveLECredentials(_)).Times(1);
  policy::DevicePolicy::EphemeralSettings ephemeral_settings;
  ephemeral_settings.global_ephemeral_users_enabled = false;
  ephemeral_settings.specific_ephemeral_users.push_back(kUser0);
  ephemeral_settings.specific_nonephemeral_users.push_back(kUser1);
  EXPECT_CALL(*mock_device_policy_, GetEphemeralSettings(_))
      .WillRepeatedly(SetEphemeralSettings(ephemeral_settings));

  auto result = homedirs_->RemoveCryptohomesBasedOnPolicy();
  EXPECT_EQ(result, HomeDirs::CryptohomesRemovedStatus::kSome);

  // Ephemeral vaults are removed.
  EXPECT_FALSE(platform_.DirectoryExists(users_[0].homedir_path));
  // Non-ephemeral vaults still exists.
  EXPECT_TRUE(platform_.DirectoryExists(users_[2].homedir_path));
  EXPECT_TRUE(platform_.DirectoryExists(users_[1].homedir_path));
  // Owner's vault still exists.
  EXPECT_TRUE(platform_.DirectoryExists(users_[kOwnerIndex].homedir_path));
}

TEST_P(HomeDirsTest, CreateCryptohome) {
  const Username kNewUserId("some_new_user");
  const ObfuscatedUsername kHashedNewUserId =
      brillo::cryptohome::home::SanitizeUserName(kNewUserId);
  const base::FilePath kNewUserPath = UserPath(kHashedNewUserId);

  EXPECT_TRUE(homedirs_->Create(kNewUserId));
  EXPECT_TRUE(platform_.DirectoryExists(kNewUserPath));
}

TEST_P(HomeDirsTest, RemoveCryptohome) {
  const Username kNewUserId("some_new_user");
  const ObfuscatedUsername kHashedNewUserId =
      brillo::cryptohome::home::SanitizeUserName(kNewUserId);
  const base::FilePath kNewUserPath = UserPath(kHashedNewUserId);

  EXPECT_TRUE(homedirs_->Create(kNewUserId));
  EXPECT_TRUE(platform_.DirectoryExists(kNewUserPath));

  EXPECT_CALL(platform_, IsDirectoryMounted(_)).WillOnce(Return(true));
  EXPECT_FALSE(homedirs_->Remove(kHashedNewUserId));
  EXPECT_TRUE(platform_.DirectoryExists(kNewUserPath));

  EXPECT_CALL(platform_, IsDirectoryMounted(_)).WillRepeatedly(Return(false));
  EXPECT_TRUE(homedirs_->Remove(kHashedNewUserId));
  EXPECT_FALSE(platform_.DirectoryExists(kNewUserPath));
}

TEST_P(HomeDirsTest, ComputeDiskUsage) {
  // /home/.shadow/$hash/mount in production code.
  base::FilePath mount_dir = users_[0].homedir_path.Append(kMountDir);
  // /home/.shadow/$hash/vault in production code.
  base::FilePath vault_dir = users_[0].homedir_path.Append(kEcryptfsVaultDir);
  // /home/user/$hash in production code and here in unit test.
  base::FilePath user_dir = users_[0].user_path;

  constexpr int64_t mount_bytes = 123456789012345;
  constexpr int64_t vault_bytes = 98765432154321;

  EXPECT_CALL(platform_, ComputeDirectoryDiskUsage(mount_dir))
      .WillRepeatedly(Return(mount_bytes));
  EXPECT_CALL(platform_, ComputeDirectoryDiskUsage(vault_dir))
      .WillRepeatedly(Return(vault_bytes));
  EXPECT_CALL(platform_, ComputeDirectoryDiskUsage(user_dir)).Times(0);

  const int64_t expected_bytes =
      ShouldTestEcryptfs() ? vault_bytes : mount_bytes;
  EXPECT_EQ(expected_bytes, homedirs_->ComputeDiskUsage(users_[0].name));
}

TEST_P(HomeDirsTest, ComputeDiskUsageEphemeral) {
  // /home/.shadow/$hash/mount in production code.
  base::FilePath mount_dir = users_[0].homedir_path.Append(kMountDir);
  // /home/.shadow/$hash/vault in production code.
  base::FilePath vault_dir = users_[0].homedir_path.Append(kEcryptfsVaultDir);
  // /home/user/$hash in production code and here in unit test.
  base::FilePath user_dir = users_[0].user_path;

  // Ephemeral users have no vault.
  EXPECT_TRUE(platform_.DeletePathRecursively(users_[0].homedir_path));

  constexpr int64_t userdir_bytes = 349857223479;

  EXPECT_CALL(platform_, ComputeDirectoryDiskUsage(mount_dir)).Times(0);
  EXPECT_CALL(platform_, ComputeDirectoryDiskUsage(vault_dir)).Times(0);
  EXPECT_CALL(platform_, ComputeDirectoryDiskUsage(user_dir))
      .WillRepeatedly(Return(userdir_bytes));

  int64_t expected_bytes = userdir_bytes;
  EXPECT_EQ(expected_bytes, homedirs_->ComputeDiskUsage(users_[0].name));
}

TEST_P(HomeDirsTest, ComputeDiskUsageWithNonexistentUser) {
  // If the specified user doesn't exist, there is no directory for the user, so
  // ComputeDiskUsage should return 0.
  const Username kNonExistentUserId("non_existent_user");
  EXPECT_EQ(0, homedirs_->ComputeDiskUsage(kNonExistentUserId));
}

TEST_P(HomeDirsTest, GetTrackedDirectoryForDirCrypto) {
  // /home/.shadow/$hash/mount in production code.
  base::FilePath mount_dir = users_[0].homedir_path.Append(kMountDir);
  // /home/.shadow/$hash/vault in production code.
  base::FilePath vault_dir = users_[0].homedir_path.Append(kEcryptfsVaultDir);

  const char* const kDirectories[] = {
      "aaa",
      "bbb",
      "bbb/ccc",
      "bbb/ccc/ddd",
  };
  // Prepare directories.
  for (const auto& directory : kDirectories) {
    const base::FilePath path = mount_dir.Append(base::FilePath(directory));
    ASSERT_TRUE(platform_.CreateDirectory(path));
    std::string name = path.BaseName().value();
    ASSERT_TRUE(platform_.SetExtendedFileAttribute(
        path, kTrackedDirectoryNameAttribute, name.data(), name.length()));
  }

  // Use GetTrackedDirectoryForDirCrypto() to get the path.
  // When dircrypto is being used and we don't have the key, the returned path
  // will be encrypted, but here we just get the same path.
  for (const auto& directory : kDirectories) {
    SCOPED_TRACE(directory);
    base::FilePath result;
    EXPECT_TRUE(homedirs_->GetTrackedDirectory(
        users_[0].homedir_path, base::FilePath(directory), &result));
    if (ShouldTestEcryptfs()) {
      EXPECT_EQ(vault_dir.Append(base::FilePath(directory)).value(),
                result.value());
    } else {
      EXPECT_EQ(mount_dir.Append(base::FilePath(directory)).value(),
                result.value());
    }
  }

  // TODO(chromium:1141301, dlunev): GetTrackedDirectory always returns true for
  // ecryptfs. Figure out what should actually be the behaviour in the case.
  if (!ShouldTestEcryptfs()) {
    // Return false for unknown directories.
    base::FilePath result;
    EXPECT_FALSE(homedirs_->GetTrackedDirectory(
        users_[0].homedir_path, base::FilePath("zzz"), &result));
    EXPECT_FALSE(homedirs_->GetTrackedDirectory(
        users_[0].homedir_path, base::FilePath("aaa/zzz"), &result));
  }
}

TEST_P(HomeDirsTest, GetUnmountedAndroidDataCount) {
  if (ShouldTestEcryptfs()) {
    // We don't support Ecryptfs.
    EXPECT_EQ(0, homedirs_->GetUnmountedAndroidDataCount());
    return;
  }

  for (const auto& user : users_) {
    // Set up a root hierarchy for the encrypted version of homedir_path
    // without android-data (added a suffix _encrypted in the code to mark them
    // encrypted).
    // root
    //     |-session_manager
    //          |-policy
    base::FilePath root =
        user.homedir_path.Append(kMountDir).Append(kRootHomeSuffix);
    base::FilePath session_manager = root.Append("session_manager_encrypted");
    ASSERT_TRUE(platform_.CreateDirectory(session_manager));
    base::FilePath policy = session_manager.Append("policy_encrypted");
    ASSERT_TRUE(platform_.CreateDirectory(policy));
  }

  // Add android data for the first user.
  //     |-android-data
  //          |-cache
  //          |-data
  base::FilePath root =
      users_[0].homedir_path.Append(kMountDir).Append(kRootHomeSuffix);
  ASSERT_TRUE(platform_.CreateDirectory(root));
  std::string name = root.BaseName().value();
  ASSERT_TRUE(platform_.SetExtendedFileAttribute(
      root, kTrackedDirectoryNameAttribute, name.data(), name.length()));

  base::FilePath android_data = root.Append("android-data_encrypted");
  ASSERT_TRUE(platform_.CreateDirectory(android_data));
  base::FilePath data = android_data.Append("data_encrypted");
  base::FilePath cache = android_data.Append("cache_encrypted");
  ASSERT_TRUE(platform_.CreateDirectory(data));
  ASSERT_TRUE(platform_.CreateDirectory(cache));
  ASSERT_TRUE(platform_.SetOwnership(cache, kAndroidSystemRealUid,
                                     kAndroidSystemRealUid, false));

  // Expect 1 home directory with android-data: homedir_paths_[0].
  EXPECT_EQ(1, homedirs_->GetUnmountedAndroidDataCount());
}

TEST_P(HomeDirsTest, GetHomedirsAllMounted) {
  std::vector<bool> all_mounted(users_.size(), true);
  std::set<ObfuscatedUsername> hashes, got_hashes;

  for (int i = 0; i < users_.size(); i++) {
    hashes.insert(users_[i].obfuscated);
  }

  EXPECT_CALL(platform_, AreDirectoriesMounted(_))
      .WillOnce(Return(all_mounted));
  auto dirs = homedirs_->GetHomeDirs();

  for (const auto& dir : dirs) {
    EXPECT_TRUE(dir.is_mounted);
    got_hashes.insert(dir.obfuscated);
  }
  EXPECT_EQ(hashes, got_hashes);
}

TEST_P(HomeDirsTest, GetHomedirsSomeMounted) {
  std::vector<bool> some_mounted(users_.size());
  std::set<ObfuscatedUsername> hashes, got_hashes;

  for (int i = 0; i < users_.size(); i++) {
    hashes.insert(users_[i].obfuscated);
    some_mounted[i] = i % 2;
  }

  EXPECT_CALL(platform_, AreDirectoriesMounted(_))
      .WillOnce(Return(some_mounted));
  auto dirs = homedirs_->GetHomeDirs();
  for (int i = 0; i < users_.size(); i++) {
    EXPECT_EQ(dirs[i].is_mounted, some_mounted[i]);
    got_hashes.insert(dirs[i].obfuscated);
  }
  EXPECT_EQ(hashes, got_hashes);
}

// Test that deleting the /home/user/<hash> paths doesn't affect homedir
// enumeration.
TEST_P(HomeDirsTest, GetHomedirsSomeMountedUserPathDeleted) {
  std::vector<bool> some_mounted(users_.size());
  std::set<ObfuscatedUsername> hashes, got_hashes;

  for (int i = 0; i < users_.size(); i++) {
    hashes.insert(users_[i].obfuscated);
    some_mounted[i] = i % 2;
    ASSERT_TRUE(platform_.DeletePathRecursively(users_[i].user_path));
  }

  EXPECT_CALL(platform_, AreDirectoriesMounted(_))
      .WillOnce(Return(some_mounted));
  auto dirs = homedirs_->GetHomeDirs();
  for (int i = 0; i < users_.size(); i++) {
    EXPECT_EQ(dirs[i].is_mounted, some_mounted[i]);
    got_hashes.insert(dirs[i].obfuscated);
  }
  EXPECT_EQ(hashes, got_hashes);
}

class HomeDirsVaultTest : public ::testing::Test {
 public:
  HomeDirsVaultTest()
      : user_({.obfuscated = ObfuscatedUsername("foo"),
               .homedir_path =
                   base::FilePath(UserPath(ObfuscatedUsername("foo")))}),
        key_reference_({.fek_sig = brillo::SecureBlob("random keyref")}) {}
  ~HomeDirsVaultTest() override = default;

  void ExpectLogicalVolumeStatefulPartition(
      MockPlatform* platform,
      HomeDirs* homedirs,
      const ObfuscatedUsername& obfuscated_username,
      bool existing_cryptohome) {
    brillo::LogicalVolume lv(LogicalVolumePrefix(obfuscated_username)
                                 .append(kDmcryptDataContainerSuffix),
                             "stateful", nullptr);

    EXPECT_CALL(*platform, GetStatefulDevice())
        .WillRepeatedly(Return(base::FilePath("/dev/mmcblk0")));
    EXPECT_CALL(*platform, GetBlkSize(_, _))
        .WillRepeatedly(
            DoAll(SetArgPointee<1>(1024 * 1024 * 1024), Return(true)));
    EXPECT_CALL(*platform, IsStatefulLogicalVolumeSupported())
        .WillRepeatedly(Return(true));
    brillo::MockLogicalVolumeManager* lvm =
        platform->GetFake()->GetMockLogicalVolumeManager();
    if (existing_cryptohome) {
      EXPECT_CALL(*lvm, GetLogicalVolume(_, _)).WillRepeatedly(Return(lv));
    } else {
      EXPECT_CALL(*lvm, GetLogicalVolume(_, _))
          .WillRepeatedly(Return(std::nullopt));
    }
  }

 protected:
  struct HomedirsTestCase {
    std::string name;
    bool lvm_supported;
    bool fscrypt_supported;
    EncryptedContainerType existing_container_type;
    CryptohomeVault::Options options;

    EncryptedContainerType expected_type;
    MountError expected_error;
  };

  const UserInfo user_;
  const FileSystemKeyReference key_reference_;

  void PrepareTestCase(const HomedirsTestCase& test_case,
                       MockPlatform* platform,
                       HomeDirs* homedirs) {
    if (test_case.lvm_supported) {
      auto type = test_case.existing_container_type;
      ExpectLogicalVolumeStatefulPartition(
          platform, homedirs, user_.obfuscated,
          type == EncryptedContainerType::kDmcrypt);
      homedirs->set_lvm_migration_enabled(true);
    }

    dircrypto::KeyState root_keystate =
        test_case.fscrypt_supported ? dircrypto::KeyState::NO_KEY
                                    : dircrypto::KeyState::NOT_SUPPORTED;
    ON_CALL(*platform, GetDirCryptoKeyState(ShadowRoot()))
        .WillByDefault(Return(root_keystate));

    switch (test_case.existing_container_type) {
      case EncryptedContainerType::kEcryptfs:
        ASSERT_TRUE(platform->CreateDirectory(
            GetEcryptfsUserVaultPath(user_.obfuscated)));
        ASSERT_TRUE(
            platform->CreateDirectory(GetUserMountDirectory(user_.obfuscated)));
        break;
      case EncryptedContainerType::kFscrypt:
        ASSERT_TRUE(
            platform->CreateDirectory(GetUserMountDirectory(user_.obfuscated)));
        ON_CALL(*platform,
                GetDirCryptoKeyState(GetUserMountDirectory(user_.obfuscated)))
            .WillByDefault(Return(dircrypto::KeyState::ENCRYPTED));
        break;
      case EncryptedContainerType::kEcryptfsToFscrypt:
        ASSERT_TRUE(platform->CreateDirectory(
            GetEcryptfsUserVaultPath(user_.obfuscated)));
        ASSERT_TRUE(
            platform->CreateDirectory(GetUserMountDirectory(user_.obfuscated)));
        ON_CALL(*platform,
                GetDirCryptoKeyState(GetUserMountDirectory(user_.obfuscated)))
            .WillByDefault(Return(dircrypto::KeyState::ENCRYPTED));
        break;
      default:
        // kDmcrypt is handled above.
        // kEphemeral doesn't need special preparations.
        break;
    }
  }
};

namespace {
TEST_F(HomeDirsVaultTest, PickVaultType) {
  const std::vector<HomeDirsVaultTest::HomedirsTestCase> test_cases = {
      {
          .name = "new_ecryptfs_allowed",
          .lvm_supported = false,
          .fscrypt_supported = false,
          .existing_container_type = EncryptedContainerType::kUnknown,
          .options = {},
          .expected_type = EncryptedContainerType::kEcryptfs,
          .expected_error = MOUNT_ERROR_NONE,
      },
      {
          .name = "new_ecryptfs_block_no_effect",
          .lvm_supported = false,
          .fscrypt_supported = false,
          .existing_container_type = EncryptedContainerType::kUnknown,
          .options = {.block_ecryptfs = true},
          .expected_type = EncryptedContainerType::kEcryptfs,
          .expected_error = MOUNT_ERROR_NONE,
      },
      {
          .name = "new_ecryptfs_cant_migrate",
          .lvm_supported = false,
          .fscrypt_supported = false,
          .existing_container_type = EncryptedContainerType::kUnknown,
          .options = {.migrate = true},
          .expected_type = EncryptedContainerType::kUnknown,
          .expected_error = MOUNT_ERROR_UNEXPECTED_MOUNT_TYPE,
      },
      {
          .name = "new_ecryptfs_forced",
          .lvm_supported = false,
          .fscrypt_supported = true,
          .existing_container_type = EncryptedContainerType::kUnknown,
          .options = {.force_type = EncryptedContainerType::kEcryptfs},
          .expected_type = EncryptedContainerType::kEcryptfs,
          .expected_error = MOUNT_ERROR_NONE,
      },
      {
          .name = "new_fscrypt",
          .lvm_supported = false,
          .fscrypt_supported = true,
          .existing_container_type = EncryptedContainerType::kUnknown,
          .options = {},
          .expected_type = EncryptedContainerType::kFscrypt,
          .expected_error = MOUNT_ERROR_NONE,
      },
      {
          .name = "existing_ecryptfs_allowed",
          .lvm_supported = false,
          .fscrypt_supported = true,
          .existing_container_type = EncryptedContainerType::kEcryptfs,
          .options = {},
          .expected_type = EncryptedContainerType::kEcryptfs,
          .expected_error = MOUNT_ERROR_NONE,
      },
      {
          .name = "existing_ecryptfs_not_allowed",
          .lvm_supported = false,
          .fscrypt_supported = true,
          .existing_container_type = EncryptedContainerType::kEcryptfs,
          .options = {.block_ecryptfs = true},
          .expected_type = EncryptedContainerType::kUnknown,
          .expected_error = MOUNT_ERROR_OLD_ENCRYPTION,
      },
      {
          .name = "existing_ecryptfs_migrate_to_fscrypt",
          .lvm_supported = false,
          .fscrypt_supported = true,
          .existing_container_type = EncryptedContainerType::kEcryptfs,
          .options = {.migrate = true},
          .expected_type = EncryptedContainerType::kEcryptfsToFscrypt,
          .expected_error = MOUNT_ERROR_NONE,
      },
      {
          .name = "existing_fscrypt",
          .lvm_supported = false,
          .fscrypt_supported = true,
          .existing_container_type = EncryptedContainerType::kFscrypt,
          .options = {},
          .expected_type = EncryptedContainerType::kFscrypt,
          .expected_error = MOUNT_ERROR_NONE,
      },
      {
          .name = "existing_fscrypt_force_ignored",
          .lvm_supported = false,
          .fscrypt_supported = true,
          .existing_container_type = EncryptedContainerType::kFscrypt,
          .options = {.force_type = EncryptedContainerType::kEcryptfs},
          .expected_type = EncryptedContainerType::kFscrypt,
          .expected_error = MOUNT_ERROR_NONE,
      },
      {
          .name = "existing_migration",
          .lvm_supported = false,
          .fscrypt_supported = true,
          .existing_container_type = EncryptedContainerType::kEcryptfsToFscrypt,
          .options = {.migrate = true},
          .expected_type = EncryptedContainerType::kEcryptfsToFscrypt,
          .expected_error = MOUNT_ERROR_NONE,
      },
      {
          .name = "existing_migration_without_flag",
          .lvm_supported = false,
          .fscrypt_supported = true,
          .existing_container_type = EncryptedContainerType::kEcryptfsToFscrypt,
          .options = {},
          .expected_type = EncryptedContainerType::kUnknown,
          .expected_error = MOUNT_ERROR_PREVIOUS_MIGRATION_INCOMPLETE,
      },
      {
          .name = "existing_fscrypt_migrate",
          .lvm_supported = true,
          .fscrypt_supported = true,
          .existing_container_type = EncryptedContainerType::kFscrypt,
          .options = {.migrate = true},
          .expected_type = EncryptedContainerType::kFscryptToDmcrypt,
          .expected_error = MOUNT_ERROR_NONE,
      },
      {
          .name = "existing_ecryptfs_migrate_to_dmcrypt",
          .lvm_supported = true,
          .fscrypt_supported = true,
          .existing_container_type = EncryptedContainerType::kEcryptfs,
          .options = {.migrate = true},
          .expected_type = EncryptedContainerType::kEcryptfsToDmcrypt,
          .expected_error = MOUNT_ERROR_NONE,
      },
      {
          .name = "new_lvm",
          .lvm_supported = true,
          .fscrypt_supported = true,
          .existing_container_type = EncryptedContainerType::kUnknown,
          .options = {},
          .expected_type = EncryptedContainerType::kDmcrypt,
          .expected_error = MOUNT_ERROR_NONE,
      },
      {
          .name = "existing_lvm",
          .lvm_supported = true,
          .fscrypt_supported = true,
          .existing_container_type = EncryptedContainerType::kDmcrypt,
          .options = {},
          .expected_type = EncryptedContainerType::kDmcrypt,
          .expected_error = MOUNT_ERROR_NONE,
      },
  };

  for (const auto& test_case : test_cases) {
    NiceMock<MockPlatform> platform;
    std::unique_ptr<EncryptedContainerFactory> container_factory =
        std::make_unique<EncryptedContainerFactory>(
            &platform, std::make_unique<FakeKeyring>(),
            std::make_unique<BackingDeviceFactory>(&platform));

    std::unique_ptr<CryptohomeVaultFactory> vault_factory =
        std::make_unique<CryptohomeVaultFactory>(&platform,
                                                 std::move(container_factory));

    if (test_case.lvm_supported) {
      std::shared_ptr<brillo::LvmCommandRunner> command_runner =
          std::make_shared<brillo::MockLvmCommandRunner>();
      brillo::VolumeGroup vg("STATEFUL", command_runner);
      brillo::Thinpool thinpool("thinpool", "STATEFUL", command_runner);
      vault_factory->CacheLogicalVolumeObjects(vg, thinpool);
    }

    HomeDirs homedirs(&platform,
                      std::make_unique<policy::PolicyProvider>(
                          std::make_unique<policy::MockDevicePolicy>()),
                      HomeDirs::RemoveCallback(), vault_factory.get());

    PrepareTestCase(test_case, &platform, &homedirs);
    auto vault_type_or =
        homedirs.PickVaultType(user_.obfuscated, test_case.options);

    if (test_case.expected_error == MOUNT_ERROR_NONE) {
      ASSERT_THAT(vault_type_or, IsOk()) << "TestCase: " << test_case.name;
      EXPECT_THAT(vault_type_or.value(), Eq(test_case.expected_type))
          << "TestCase: " << test_case.name;
    } else {
      ASSERT_THAT(vault_type_or, IsError(test_case.expected_error))
          << "TestCase: " << test_case.name;
    }
  }
}
}  // namespace

}  // namespace cryptohome
