// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/keyset_management.h"

#include <algorithm>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/test/task_environment.h>
#include <brillo/cryptohome.h>
#include <brillo/data_encoding.h>
#include <brillo/secure_blob.h>
#include <base/test/test_future.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec/factory/tpm2_simulator_factory_for_test.h>
#include <libhwsec/frontend/cryptohome/mock_frontend.h>
#include <libhwsec/frontend/pinweaver/mock_frontend.h>
#include <libhwsec-foundation/crypto/hmac.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/auth_blocks/pin_weaver_auth_block.h"
#include "cryptohome/auth_blocks/scrypt_auth_block.h"
#include "cryptohome/auth_blocks/tpm_bound_to_pcr_auth_block.h"
#include "cryptohome/auth_blocks/tpm_ecc_auth_block.h"
#include "cryptohome/auth_blocks/tpm_not_bound_to_pcr_auth_block.h"
#include "cryptohome/crypto.h"
#include "cryptohome/fake_features.h"
#include "cryptohome/filesystem_layout.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/le_credential_manager_impl.h"
#include "cryptohome/mock_cryptohome_keys_manager.h"
#include "cryptohome/mock_platform.h"
#include "cryptohome/mock_vault_keyset.h"
#include "cryptohome/mock_vault_keyset_factory.h"
#include "cryptohome/storage/file_system_keyset.h"
#include "cryptohome/timestamp.pb.h"
#include "cryptohome/vault_keyset.h"

using ::cryptohome::error::CryptohomeCryptoError;
using ::cryptohome::error::CryptohomeError;
using ::cryptohome::error::ErrorActionSet;
using ::cryptohome::error::PossibleAction;
using ::cryptohome::error::PrimaryAction;
using ::hwsec_foundation::error::testing::IsOk;
using ::hwsec_foundation::error::testing::NotOk;
using ::hwsec_foundation::error::testing::ReturnError;
using ::hwsec_foundation::error::testing::ReturnValue;
using ::hwsec_foundation::status::StatusChain;
using ::testing::_;
using ::testing::ContainerEq;
using ::testing::DoAll;
using ::testing::ElementsAre;
using ::testing::EndsWith;
using ::testing::Eq;
using ::testing::MatchesRegex;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::SetArgPointee;
using ::testing::StrEq;
using ::testing::UnorderedElementsAre;

using base::test::TestFuture;

namespace cryptohome {

namespace {

struct UserPassword {
  const char* name;
  const char* password;
};

constexpr char kUser0[] = "First User";
constexpr char kUserPassword0[] = "user0_pass";

constexpr char kCredDirName[] = "low_entropy_creds";
constexpr char kPasswordLabel[] = "password";
constexpr char kPinLabel[] = "lecred1";

constexpr char kNewPasskey[] = "new pass";
constexpr char kNewLabel[] = "new_label";
constexpr char kSalt[] = "salt";

const brillo::SecureBlob kInitialBlob64(64, 'A');
const brillo::SecureBlob kInitialBlob32(32, 'A');
const brillo::SecureBlob kAdditionalBlob32(32, 'B');
const brillo::SecureBlob kInitialBlob16(16, 'C');
const brillo::SecureBlob kAdditionalBlob16(16, 'D');

using CreateTestFuture = TestFuture<CryptohomeStatus,
                                    std::unique_ptr<KeyBlobs>,
                                    std::unique_ptr<AuthBlockState>>;
}  // namespace

class KeysetManagementTest : public ::testing::Test {
 public:
  KeysetManagementTest()
      : crypto_(&hwsec_, &pinweaver_, &cryptohome_keys_manager_, nullptr) {
    CHECK(temp_dir_.CreateUniqueTempDir());
  }

  ~KeysetManagementTest() override = default;

  // Not copyable or movable
  KeysetManagementTest(const KeysetManagementTest&) = delete;
  KeysetManagementTest& operator=(const KeysetManagementTest&) = delete;
  KeysetManagementTest(KeysetManagementTest&&) = delete;
  KeysetManagementTest& operator=(KeysetManagementTest&&) = delete;

  void SetUp() override {
    EXPECT_CALL(hwsec_, IsEnabled()).WillRepeatedly(ReturnValue(false));
    EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(false));
    EXPECT_CALL(hwsec_, IsSealingSupported())
        .WillRepeatedly(ReturnValue(false));
    EXPECT_CALL(pinweaver_, IsEnabled()).WillRepeatedly(ReturnValue(false));

    mock_vault_keyset_factory_ = new NiceMock<MockVaultKeysetFactory>();
    ON_CALL(*mock_vault_keyset_factory_, New(&platform_, &crypto_))
        .WillByDefault([this](auto&&, auto&&) {
          auto* vk = new VaultKeyset();
          vk->Initialize(&platform_, &crypto_);
          return vk;
        });
    keyset_management_ = std::make_unique<KeysetManagement>(
        &platform_, &crypto_,
        std::unique_ptr<VaultKeysetFactory>(mock_vault_keyset_factory_));
    file_system_keyset_ = FileSystemKeyset::CreateRandom();
    auth_state_ = std::make_unique<AuthBlockState>();
    AddUser(kUser0, kUserPassword0);
    PrepareDirectoryStructure();
  }

  // Returns location of on-disk hash tree directory.
  base::FilePath CredDirPath() {
    return temp_dir_.GetPath().Append(kCredDirName);
  }

 protected:
  base::test::TaskEnvironment task_environment_;
  NiceMock<MockPlatform> platform_;
  NiceMock<hwsec::MockCryptohomeFrontend> hwsec_;
  NiceMock<hwsec::MockPinWeaverFrontend> pinweaver_;
  NiceMock<MockCryptohomeKeysManager> cryptohome_keys_manager_;
  Crypto crypto_;
  FileSystemKeyset file_system_keyset_;
  MockVaultKeysetFactory* mock_vault_keyset_factory_;
  std::unique_ptr<KeysetManagement> keyset_management_;
  base::ScopedTempDir temp_dir_;
  KeyBlobs key_blobs_;
  std::unique_ptr<AuthBlockState> auth_state_;
  struct UserInfo {
    Username name;
    ObfuscatedUsername obfuscated;
    brillo::SecureBlob passkey;
    base::FilePath homedir_path;
    base::FilePath user_path;
    KeyData key_data;
    SerializedVaultKeyset_SignatureChallengeInfo
        challenge_credentials_keyset_info;
  };

  const CryptohomeError::ErrorLocationPair kErrorLocationForTesting1 =
      CryptohomeError::ErrorLocationPair(
          static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(1),
          std::string("Testing1"));

  // SETUPers

  // Information about users' keyset_management. The order of users is equal to
  // kUsers.
  std::vector<UserInfo> users_;

  void AddUser(const char* name, const char* password) {
    Username username(name);
    ObfuscatedUsername obfuscated =
        brillo::cryptohome::home::SanitizeUserName(username);
    brillo::SecureBlob passkey(password);

    UserInfo info = {username, obfuscated, passkey, UserPath(obfuscated),
                     brillo::cryptohome::home::GetHashedUserPath(obfuscated)};
    users_.push_back(info);
  }

  void PrepareDirectoryStructure() {
    ASSERT_TRUE(platform_.CreateDirectory(ShadowRoot()));
    ASSERT_TRUE(platform_.CreateDirectory(
        brillo::cryptohome::home::GetUserPathPrefix()));
    // We only need the homedir path, not the vault/mount paths.
    for (const auto& user : users_) {
      ASSERT_TRUE(platform_.CreateDirectory(user.homedir_path));
    }
  }

  KeyData DefaultKeyData() {
    KeyData key_data;
    key_data.set_label(kPasswordLabel);
    return key_data;
  }

  KeyData DefaultLEKeyData() {
    KeyData key_data;
    key_data.set_label(kPinLabel);
    key_data.mutable_policy()->set_low_entropy_credential(true);
    return key_data;
  }

  void KeysetSetUpWithKeyDataAndKeyBlobs(const KeyData& key_data) {
    for (auto& user : users_) {
      VaultKeyset vk;
      vk.Initialize(&platform_, &crypto_);
      vk.CreateFromFileSystemKeyset(file_system_keyset_);
      vk.SetKeyData(key_data);
      key_blobs_.vkk_key = kInitialBlob32;
      key_blobs_.vkk_iv = kInitialBlob16;
      key_blobs_.chaps_iv = kInitialBlob16;

      if (key_data.has_policy() && key_data.policy().low_entropy_credential()) {
        PinWeaverAuthBlockState pin_state = {
            .le_label = 0xbaadf00d,
            .salt = brillo::SecureBlob("fake salt"),
            .chaps_iv = brillo::SecureBlob("fake chaps IV"),
            .fek_iv = brillo::SecureBlob("fake file encryption IV"),
            .reset_salt = brillo::SecureBlob("more fake salt"),
        };
        auth_state_->state = pin_state;

      } else {
        TpmBoundToPcrAuthBlockState pcr_state = {
            .salt = brillo::SecureBlob("fake salt"),
            .tpm_key = brillo::SecureBlob("fake tpm key"),
            .extended_tpm_key = brillo::SecureBlob("fake extended tpm key")};
        auth_state_->state = pcr_state;
      }

      ASSERT_THAT(vk.EncryptEx(key_blobs_, *auth_state_), IsOk());
      ASSERT_TRUE(
          vk.Save(user.homedir_path.Append(kKeyFile).AddExtension("0")));
    }
  }

  void KeysetSetUpWithoutKeyDataAndKeyBlobs() {
    for (auto& user : users_) {
      VaultKeyset vk;
      vk.Initialize(&platform_, &crypto_);
      vk.CreateFromFileSystemKeyset(file_system_keyset_);
      key_blobs_.vkk_key = kInitialBlob32;
      key_blobs_.vkk_iv = kInitialBlob16;
      key_blobs_.chaps_iv = kInitialBlob16;

      TpmBoundToPcrAuthBlockState pcr_state = {.salt =
                                                   brillo::SecureBlob(kSalt)};
      auth_state_->state = pcr_state;

      ASSERT_THAT(vk.EncryptEx(key_blobs_, *auth_state_), IsOk());
      ASSERT_TRUE(
          vk.Save(user.homedir_path.Append(kKeyFile).AddExtension("0")));
    }
  }

  // TESTers

  void VerifyKeysetIndicies(const std::vector<int>& expected) {
    std::vector<int> indicies;
    ASSERT_TRUE(
        keyset_management_->GetVaultKeysets(users_[0].obfuscated, &indicies));
    EXPECT_THAT(indicies, ContainerEq(expected));
  }

  void VerifyKeysetPresentWithDefaultKeyBlobsAtIndex(
      const ObfuscatedUsername& obfuscated_username,
      const std::string& label,
      int index) {
    ASSERT_TRUE(key_blobs_.vkk_key.has_value());
    ASSERT_TRUE(key_blobs_.vkk_iv.has_value());
    ASSERT_TRUE(key_blobs_.chaps_iv.has_value());
    VerifyWrappedKeysetPresentAtIndex(
        obfuscated_username, key_blobs_.vkk_key.value(),
        key_blobs_.vkk_iv.value(), key_blobs_.chaps_iv.value(), label, index);
  }

  void VerifyWrappedKeysetNotPresent(
      const ObfuscatedUsername& obfuscated_username,
      const brillo::SecureBlob& vkk_key,
      const brillo::SecureBlob& vkk_iv,
      const brillo::SecureBlob& chaps_iv,
      const std::string& label) {
    KeyBlobs key_blobs;
    key_blobs.vkk_key = vkk_key;
    key_blobs.vkk_iv = vkk_iv;
    key_blobs.chaps_iv = chaps_iv;
    MountStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
        keyset_management_->GetValidKeyset(obfuscated_username,
                                           std::move(key_blobs), label);
    ASSERT_THAT(vk_status, NotOk());
  }

  void VerifyWrappedKeysetPresentAtIndex(
      const ObfuscatedUsername& obfuscated_username,
      const brillo::SecureBlob& vkk_key,
      const brillo::SecureBlob& vkk_iv,
      const brillo::SecureBlob& chaps_iv,
      const std::string& label,
      int index) {
    KeyBlobs key_blobs;
    key_blobs.vkk_key = vkk_key;
    key_blobs.vkk_iv = vkk_iv;
    key_blobs.chaps_iv = chaps_iv;
    MountStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
        keyset_management_->GetValidKeyset(obfuscated_username,
                                           std::move(key_blobs), label);
    ASSERT_THAT(vk_status, IsOk());
    EXPECT_EQ(vk_status.value()->GetLegacyIndex(), index);
    EXPECT_TRUE(vk_status.value()->HasWrappedChapsKey());
    EXPECT_TRUE(vk_status.value()->HasWrappedResetSeed());
  }
};

// Test the scenario when `AddInitialKeyset()` fails due to an error
// in `Save()`.
TEST_F(KeysetManagementTest, AddInitialKeysetSaveError) {
  // SETUP

  users_[0].key_data = DefaultKeyData();
  auto vk = std::make_unique<NiceMock<MockVaultKeyset>>();
  EXPECT_CALL(*vk, Save(_)).WillOnce(Return(false));
  EXPECT_CALL(*mock_vault_keyset_factory_, New(&platform_, &crypto_))
      .WillOnce(Return(vk.release()));

  TpmBoundToPcrAuthBlockState pcr_state = {.salt = brillo::SecureBlob(kSalt)};
  auth_state_ = std::make_unique<AuthBlockState>();
  auth_state_->state = pcr_state;
  users_[0].key_data = DefaultKeyData();

  // TEST

  auto status_or = keyset_management_->AddInitialKeyset(
      VaultKeysetIntent{.backup = false}, users_[0].obfuscated,
      users_[0].key_data, users_[0].challenge_credentials_keyset_info,
      file_system_keyset_, std::move(key_blobs_), std::move(auth_state_));

  // VERIFY

  ASSERT_THAT(status_or, NotOk());
  EXPECT_EQ(status_or.status()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
}

// Fail to get keyset due to invalid keyblobs.
TEST_F(KeysetManagementTest, GetValidKeysetInvalidCreds) {
  // SETUP

  KeysetSetUpWithKeyDataAndKeyBlobs(DefaultKeyData());

  KeyBlobs invalid_key_blobs;
  invalid_key_blobs.vkk_key = brillo::SecureBlob("vkk_key");
  invalid_key_blobs.chaps_iv = brillo::SecureBlob("chaps_iv");
  invalid_key_blobs.vkk_iv = brillo::SecureBlob("vkk_iv");

  // TEST
  // It uses the right and expected label but wrong credentials.
  MountStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
      keyset_management_->GetValidKeyset(users_[0].obfuscated,
                                         invalid_key_blobs, kPasswordLabel);
  ASSERT_THAT(vk_status, NotOk());
  EXPECT_EQ(vk_status.status()->mount_error(),
            MountError::MOUNT_ERROR_KEY_FAILURE);
}

// Fail to add new keyset due to failed disk write.
TEST_F(KeysetManagementTest, AddKeysetSaveFail) {
  // SETUP
  KeysetSetUpWithKeyDataAndKeyBlobs(DefaultKeyData());

  MountStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
      keyset_management_->GetValidKeyset(users_[0].obfuscated,
                                         std::move(key_blobs_), kPasswordLabel);
  ASSERT_THAT(vk_status, IsOk());
  KeyData new_data;
  new_data.set_label(kNewLabel);

  KeyBlobs new_key_blobs;
  new_key_blobs.vkk_key = kAdditionalBlob32;
  new_key_blobs.chaps_iv = kAdditionalBlob16;
  new_key_blobs.vkk_iv = kAdditionalBlob16;

  // Mock vk to inject encryption failure on new keyset.
  auto mock_vk_to_add = new NiceMock<MockVaultKeyset>();
  // Mock vk for existing keyset.

  vk_status.value()->CreateRandomResetSeed();
  vk_status.value()->SetWrappedResetSeed(brillo::SecureBlob("reset_seed"));
  // ON_CALL(*mock_vault_keyset_factory_, New(&platform_, &crypto_))
  //    .WillByDefault(Return(mock_vk_to_add));
  EXPECT_CALL(*mock_vault_keyset_factory_, New(&platform_, &crypto_))
      .Times(2)
      .WillOnce(testing::DoDefault())
      .WillOnce(Return(mock_vk_to_add));

  // The first available slot is in indice 1 since the 0 is used by |vk|.
  EXPECT_CALL(*mock_vk_to_add,
              Save(users_[0].homedir_path.Append(kKeyFile).AddExtension("1")))
      .WillOnce(Return(false));

  // TEST
  CryptohomeStatus status = keyset_management_->AddKeyset(
      VaultKeysetIntent{.backup = false}, users_[0].obfuscated,
      new_data.label(), new_data, *vk_status.value(), std::move(new_key_blobs),
      std::move(auth_state_), false /*clobber*/);

  ASSERT_THAT(status, NotOk());
  EXPECT_EQ(status.status()->local_legacy_error(),
            CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);

  Mock::VerifyAndClearExpectations(mock_vault_keyset_factory_);

  // VERIFY
  // If we failed to save the added keyset due to disk failure, the old
  // keyset should still exist and be readable with the old credentials.

  VerifyKeysetIndicies({kInitialKeysetIndex});

  VerifyKeysetPresentWithDefaultKeyBlobsAtIndex(
      users_[0].obfuscated, kPasswordLabel, kInitialKeysetIndex);
  VerifyWrappedKeysetNotPresent(
      users_[0].obfuscated, new_key_blobs.vkk_key.value(),
      new_key_blobs.vkk_iv.value(), new_key_blobs.chaps_iv.value(),
      new_data.label());
}

// List labels.
TEST_F(KeysetManagementTest, GetVaultKeysetLabels) {
  // SETUP
  KeysetSetUpWithKeyDataAndKeyBlobs(DefaultKeyData());

  KeyData new_data;
  new_data.set_label(kNewLabel);

  KeyBlobs new_key_blobs;
  new_key_blobs.vkk_key = kAdditionalBlob32;
  new_key_blobs.vkk_iv = kAdditionalBlob16;
  new_key_blobs.chaps_iv = kAdditionalBlob16;

  TpmBoundToPcrAuthBlockState pcr_state = {.salt = brillo::SecureBlob(kSalt)};
  auto auth_state = std::make_unique<AuthBlockState>();
  auth_state->state = pcr_state;

  // TEST
  MountStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
      keyset_management_->GetValidKeyset(users_[0].obfuscated,
                                         std::move(key_blobs_), kPasswordLabel);
  ASSERT_THAT(vk_status, IsOk());

  ASSERT_THAT(keyset_management_->AddKeyset(
                  VaultKeysetIntent{.backup = false}, users_[0].obfuscated,
                  new_data.label(), new_data, *vk_status.value(),
                  std::move(new_key_blobs), std::move(auth_state), false),
              IsOk());

  // TEST

  std::vector<std::string> labels;
  EXPECT_TRUE(keyset_management_->GetVaultKeysetLabels(
      users_[0].obfuscated,
      /*include_le_label*/ true, &labels));

  // VERIFY
  // Labels of the initial and newly added keysets are returned.

  ASSERT_EQ(2, labels.size());
  EXPECT_THAT(labels, UnorderedElementsAre(kPasswordLabel, kNewLabel));
}

// List non LE labels.
TEST_F(KeysetManagementTest, GetNonLEVaultKeysetLabels) {
  // SETUP
  hwsec::Tpm2SimulatorFactoryForTest factory;
  std::unique_ptr<const hwsec::PinWeaverFrontend> pinweaver =
      factory.GetPinWeaverFrontend();
  auto le_cred_manager =
      std::make_unique<LECredentialManagerImpl>(pinweaver.get(), CredDirPath());
  crypto_.set_le_manager_for_testing(std::move(le_cred_manager));
  crypto_.Init();

  // Setup initial user.
  KeysetSetUpWithKeyDataAndKeyBlobs(DefaultKeyData());

  // Add pin credentials.
  KeyData key_data = DefaultLEKeyData();

  KeyBlobs new_key_blobs;
  new_key_blobs.vkk_key = kAdditionalBlob32;
  new_key_blobs.vkk_iv = kAdditionalBlob16;
  new_key_blobs.chaps_iv = kAdditionalBlob16;

  PinWeaverAuthBlockState pin_state;
  auto auth_state = std::make_unique<AuthBlockState>();
  auth_state->state = pin_state;

  // TEST
  MountStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
      keyset_management_->GetValidKeyset(users_[0].obfuscated,
                                         std::move(key_blobs_), kPasswordLabel);
  ASSERT_THAT(vk_status, IsOk());

  ASSERT_THAT(keyset_management_->AddKeyset(
                  VaultKeysetIntent{.backup = false}, users_[0].obfuscated,
                  key_data.label(), key_data, *vk_status.value(),
                  std::move(new_key_blobs), std::move(auth_state), false),
              IsOk());

  // TEST

  std::vector<std::string> labels;
  EXPECT_TRUE(keyset_management_->GetVaultKeysetLabels(
      users_[0].obfuscated,
      /*include_le_label*/ false, &labels));

  // VERIFY
  // Labels of only non LE credentials returned.

  ASSERT_EQ(1, labels.size());
  EXPECT_EQ(kPasswordLabel, labels[0]);
}

// List labels for legacy keyset.
TEST_F(KeysetManagementTest, GetVaultKeysetLabelsOneLegacyLabeled) {
  // SETUP

  KeysetSetUpWithoutKeyDataAndKeyBlobs();
  std::vector<std::string> labels;

  // TEST

  EXPECT_TRUE(keyset_management_->GetVaultKeysetLabels(
      users_[0].obfuscated,
      /*include_le_label*/ true, &labels));

  // VERIFY
  // Initial keyset has no key data thus shall provide "legacy" label.

  ASSERT_EQ(1, labels.size());
  EXPECT_EQ(base::StringPrintf("%s%d", kKeyLegacyPrefix, kInitialKeysetIndex),
            labels[0]);
}

// Fails to remove keyset due to invalid index.
TEST_F(KeysetManagementTest, ForceRemoveKeysetInvalidIndex) {
  // SETUP

  KeysetSetUpWithKeyDataAndKeyBlobs(DefaultKeyData());

  // TEST

  ASSERT_FALSE(
      keyset_management_->ForceRemoveKeyset(users_[0].obfuscated, -1).ok());
  ASSERT_FALSE(
      keyset_management_->ForceRemoveKeyset(users_[0].obfuscated, kKeyFileMax)
          .ok());

  // VERIFY
  // Trying to delete keyset with out-of-bound index id. Nothing changes,
  // initial keyset still available with old creds.

  VerifyKeysetIndicies({kInitialKeysetIndex});

  VerifyKeysetPresentWithDefaultKeyBlobsAtIndex(
      users_[0].obfuscated, kPasswordLabel, kInitialKeysetIndex);
}

// Fails to remove keyset due to injected error.
TEST_F(KeysetManagementTest, ForceRemoveKeysetFailedDelete) {
  // SETUP

  KeysetSetUpWithKeyDataAndKeyBlobs(DefaultKeyData());
  EXPECT_CALL(platform_, DeleteFile(Property(&base::FilePath::value,
                                             EndsWith("master.0"))))  // nocheck
      .WillOnce(Return(false));

  // TEST

  ASSERT_FALSE(
      keyset_management_->ForceRemoveKeyset(users_[0].obfuscated, 0).ok());

  // VERIFY
  // Deletion fails, Nothing changes, initial keyset still available with old
  // creds.

  VerifyKeysetIndicies({kInitialKeysetIndex});

  VerifyKeysetPresentWithDefaultKeyBlobsAtIndex(
      users_[0].obfuscated, kPasswordLabel, kInitialKeysetIndex);
}

// The following tests use MOCKs for TpmState and hand-crafted vault keyset
// state. Ideally we shall have a fake tpm, but that is not feasible ATM.

TEST_F(KeysetManagementTest, ReSaveOnLoadTestRegularCreds) {
  // SETUP

  KeysetSetUpWithKeyDataAndKeyBlobs(DefaultKeyData());

  MountStatusOr<std::unique_ptr<VaultKeyset>> vk0_status =
      keyset_management_->GetValidKeyset(users_[0].obfuscated, key_blobs_,
                                         kPasswordLabel);
  ASSERT_THAT(vk0_status, IsOk());

  NiceMock<MockCryptohomeKeysManager> mock_cryptohome_keys_manager;
  EXPECT_CALL(mock_cryptohome_keys_manager, HasAnyCryptohomeKey())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_cryptohome_keys_manager, Init()).WillRepeatedly(Return());

  EXPECT_CALL(hwsec_, IsEnabled()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(hwsec_, IsSealingSupported()).WillRepeatedly(ReturnValue(true));

  crypto_.Init();

  // TEST

  // Scrypt wrapped shall be resaved when tpm present.
  EXPECT_TRUE(keyset_management_->ShouldReSaveKeyset(vk0_status.value().get()));

  // Tpm wrapped not pcr bound, but no public hash - resave.
  vk0_status.value()->SetFlags(SerializedVaultKeyset::TPM_WRAPPED |
                               SerializedVaultKeyset::SCRYPT_DERIVED);
  EXPECT_TRUE(keyset_management_->ShouldReSaveKeyset(vk0_status.value().get()));

  // Tpm wrapped pcr bound, but no public hash - resave.
  vk0_status.value()->SetFlags(SerializedVaultKeyset::TPM_WRAPPED |
                               SerializedVaultKeyset::SCRYPT_DERIVED |
                               SerializedVaultKeyset::PCR_BOUND);
  EXPECT_TRUE(keyset_management_->ShouldReSaveKeyset(vk0_status.value().get()));

  // Tpm wrapped not pcr bound, public hash - resave.
  vk0_status.value()->SetTpmPublicKeyHash(brillo::SecureBlob("public hash"));
  vk0_status.value()->SetFlags(SerializedVaultKeyset::TPM_WRAPPED |
                               SerializedVaultKeyset::SCRYPT_DERIVED);
  EXPECT_TRUE(keyset_management_->ShouldReSaveKeyset(vk0_status.value().get()));

  // Tpm wrapped pcr bound, public hash - no resave.
  vk0_status.value()->SetTpmPublicKeyHash(brillo::SecureBlob("public hash"));
  vk0_status.value()->SetFlags(SerializedVaultKeyset::TPM_WRAPPED |
                               SerializedVaultKeyset::SCRYPT_DERIVED |
                               SerializedVaultKeyset::PCR_BOUND);
  EXPECT_FALSE(
      keyset_management_->ShouldReSaveKeyset(vk0_status.value().get()));

  // Tpm wrapped pcr bound and ECC key, public hash - no resave.
  vk0_status.value()->SetTpmPublicKeyHash(brillo::SecureBlob("public hash"));
  vk0_status.value()->SetFlags(SerializedVaultKeyset::TPM_WRAPPED |
                               SerializedVaultKeyset::SCRYPT_DERIVED |
                               SerializedVaultKeyset::PCR_BOUND |
                               SerializedVaultKeyset::ECC);
  EXPECT_FALSE(
      keyset_management_->ShouldReSaveKeyset(vk0_status.value().get()));
}

TEST_F(KeysetManagementTest, ReSaveOnLoadTestLeCreds) {
  // SETUP
  hwsec::Tpm2SimulatorFactoryForTest factory;
  std::unique_ptr<const hwsec::PinWeaverFrontend> pinweaver =
      factory.GetPinWeaverFrontend();
  auto le_cred_manager =
      std::make_unique<LECredentialManagerImpl>(pinweaver.get(), CredDirPath());
  crypto_.set_le_manager_for_testing(std::move(le_cred_manager));
  crypto_.Init();

  KeysetSetUpWithKeyDataAndKeyBlobs(DefaultLEKeyData());

  MountStatusOr<std::unique_ptr<VaultKeyset>> vk0_status =
      keyset_management_->GetValidKeyset(users_[0].obfuscated, key_blobs_,
                                         kPinLabel);
  ASSERT_THAT(vk0_status, IsOk());

  EXPECT_CALL(cryptohome_keys_manager_, HasAnyCryptohomeKey())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(cryptohome_keys_manager_, Init()).WillRepeatedly(Return());

  EXPECT_CALL(hwsec_, IsEnabled()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));

  EXPECT_FALSE(
      keyset_management_->ShouldReSaveKeyset(vk0_status.value().get()));
}

TEST_F(KeysetManagementTest, RemoveLECredentials) {
  // SETUP
  hwsec::Tpm2SimulatorFactoryForTest factory;
  std::unique_ptr<const hwsec::PinWeaverFrontend> pinweaver =
      factory.GetPinWeaverFrontend();
  auto le_cred_manager =
      std::make_unique<LECredentialManagerImpl>(pinweaver.get(), CredDirPath());
  crypto_.set_le_manager_for_testing(std::move(le_cred_manager));
  crypto_.Init();

  // Setup initial user.
  KeysetSetUpWithKeyDataAndKeyBlobs(DefaultKeyData());
  MountStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
      keyset_management_->GetValidKeyset(users_[0].obfuscated,
                                         std::move(key_blobs_), kPasswordLabel);
  ASSERT_THAT(vk_status, IsOk());

  // Setup pin credentials.
  FakeFeaturesForTesting features;
  auto auth_block = std::make_unique<PinWeaverAuthBlock>(features.async,
                                                         crypto_.le_manager());

  AuthInput auth_input = {brillo::SecureBlob(kNewPasskey),
                          false,
                          users_[0].name,
                          users_[0].obfuscated,
                          /*reset_secret*/ std::nullopt,
                          vk_status->get()->GetResetSeed()};
  CreateTestFuture result;
  auth_block->Create(auth_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());
  auto [status, key_blobs, auth_state] = result.Take();

  KeyData key_data = DefaultLEKeyData();

  KeyBlobs new_key_blobs;
  new_key_blobs.vkk_key = kAdditionalBlob32;
  new_key_blobs.vkk_iv = kAdditionalBlob16;
  new_key_blobs.chaps_iv = kAdditionalBlob16;

  // TEST
  ASSERT_THAT(keyset_management_->AddKeyset(
                  VaultKeysetIntent{.backup = false}, users_[0].obfuscated,
                  key_data.label(), key_data, *vk_status.value(),
                  std::move(new_key_blobs), std::move(auth_state), false),
              IsOk());

  // When adding new keyset with an new label we expect it to have another
  // keyset.

  VerifyKeysetIndicies({kInitialKeysetIndex, kInitialKeysetIndex + 1});
  // Ensure Pin keyset was added.
  MountStatusOr<std::unique_ptr<VaultKeyset>> vk_verify =
      keyset_management_->GetValidKeyset(users_[0].obfuscated, new_key_blobs,
                                         kPinLabel);
  ASSERT_THAT(vk_verify, IsOk());

  // TEST
  keyset_management_->RemoveLECredentials(users_[0].obfuscated);

  // Verify
  vk_verify = keyset_management_->GetValidKeyset(users_[0].obfuscated,
                                                 new_key_blobs, kPinLabel);
  ASSERT_THAT(vk_verify, NotOk());

  // Make sure that the password credentials are still valid.
  vk_status = keyset_management_->GetValidKeyset(users_[0].obfuscated,
                                                 key_blobs_, kPasswordLabel);
  ASSERT_THAT(vk_status, IsOk());
}

TEST_F(KeysetManagementTest, GetValidKeysetNoValidKeyset) {
  // No valid keyset for GetValidKeyset to load.
  // Test
  MountStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
      keyset_management_->GetValidKeyset(users_[0].obfuscated, key_blobs_,
                                         kPasswordLabel);
  ASSERT_THAT(vk_status, NotOk());
  EXPECT_EQ(vk_status.status()->mount_error(), MOUNT_ERROR_VAULT_UNRECOVERABLE);
}

TEST_F(KeysetManagementTest, GetValidKeysetNoParsableKeyset) {
  // KeysetManagement has a valid keyset, but is unable to parse due to read
  // failure.
  KeysetSetUpWithKeyDataAndKeyBlobs(DefaultKeyData());

  EXPECT_CALL(platform_, ReadFile(_, _)).WillOnce(Return(false));

  MountStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
      keyset_management_->GetValidKeyset(users_[0].obfuscated, key_blobs_,
                                         kPasswordLabel);
  ASSERT_THAT(vk_status, NotOk());
  EXPECT_EQ(vk_status.status()->mount_error(), MOUNT_ERROR_VAULT_UNRECOVERABLE);
}

TEST_F(KeysetManagementTest, GetValidKeysetCryptoError) {
  // Map's all the relevant CryptoError's to their equivalent MountError
  // as per the conversion in GetValidKeyset.
  const std::map<CryptoError, MountError> kErrorMap = {
      {CryptoError::CE_TPM_FATAL, MOUNT_ERROR_VAULT_UNRECOVERABLE},
      {CryptoError::CE_OTHER_FATAL, MOUNT_ERROR_VAULT_UNRECOVERABLE},
      {CryptoError::CE_TPM_COMM_ERROR, MOUNT_ERROR_TPM_COMM_ERROR},
      {CryptoError::CE_TPM_DEFEND_LOCK, MOUNT_ERROR_TPM_DEFEND_LOCK},
      {CryptoError::CE_TPM_REBOOT, MOUNT_ERROR_TPM_NEEDS_REBOOT},
      {CryptoError::CE_OTHER_CRYPTO, MOUNT_ERROR_KEY_FAILURE},
  };

  for (const auto& [key, value] : kErrorMap) {
    // Setup
    KeysetSetUpWithoutKeyDataAndKeyBlobs();

    // Mock vk to inject decryption failure on GetValidKeyset
    auto mock_vk = new NiceMock<MockVaultKeyset>();
    EXPECT_CALL(*mock_vault_keyset_factory_, New(_, _))
        .WillOnce(Return(mock_vk));
    EXPECT_CALL(*mock_vk, Load(_)).WillOnce(Return(true));
    EXPECT_CALL(*mock_vk, DecryptEx(_))
        .WillOnce(ReturnError<CryptohomeCryptoError>(
            kErrorLocationForTesting1,
            ErrorActionSet({PossibleAction::kReboot}), key));

    MountStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
        keyset_management_->GetValidKeyset(users_[0].obfuscated, key_blobs_,
                                           "");
    ASSERT_THAT(vk_status, NotOk());
    EXPECT_EQ(vk_status.status()->mount_error(), value);
  }
}

// TODO(b/205759690, dlunev): can be removed after a stepping stone release.
TEST_F(KeysetManagementTest, GetKeysetBoundTimestamp) {
  KeysetSetUpWithKeyDataAndKeyBlobs(DefaultKeyData());

  constexpr int kTestTimestamp = 42000000;
  Timestamp timestamp;
  timestamp.set_timestamp(kTestTimestamp);
  std::string timestamp_str;
  ASSERT_TRUE(timestamp.SerializeToString(&timestamp_str));
  ASSERT_TRUE(platform_.WriteStringToFileAtomicDurable(
      UserActivityPerIndexTimestampPath(users_[0].obfuscated, 0), timestamp_str,
      kKeyFilePermissions));

  ASSERT_THAT(keyset_management_->GetKeysetBoundTimestamp(users_[0].obfuscated),
              Eq(base::Time::FromInternalValue(kTestTimestamp)));
}

// TODO(b/205759690, dlunev): can be removed after a stepping stone release.
TEST_F(KeysetManagementTest, CleanupPerIndexTimestampFiles) {
  for (int i = 0; i < 10; ++i) {
    const base::FilePath ts_file =
        UserActivityPerIndexTimestampPath(users_[0].obfuscated, i);
    ASSERT_TRUE(platform_.WriteStringToFileAtomicDurable(
        ts_file, "doesn't matter", kKeyFilePermissions));
  }
  keyset_management_->CleanupPerIndexTimestampFiles(users_[0].obfuscated);
  for (int i = 0; i < 10; ++i) {
    const base::FilePath ts_file =
        UserActivityPerIndexTimestampPath(users_[0].obfuscated, i);
    ASSERT_FALSE(platform_.FileExists(ts_file));
  }
}

// Successfully adds new keyset with KeyBlobs
TEST_F(KeysetManagementTest, AddKeysetSuccess) {
  // SETUP
  KeysetSetUpWithKeyDataAndKeyBlobs(DefaultKeyData());

  KeyData new_data;
  new_data.set_label(kNewLabel);

  KeyBlobs new_key_blobs;
  new_key_blobs.vkk_key = kAdditionalBlob32;
  new_key_blobs.vkk_iv = kAdditionalBlob16;
  new_key_blobs.chaps_iv = kAdditionalBlob16;

  TpmBoundToPcrAuthBlockState pcr_state = {.salt = brillo::SecureBlob(kSalt)};
  auto auth_state = std::make_unique<AuthBlockState>();
  auth_state->state = pcr_state;

  // TEST
  MountStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
      keyset_management_->GetValidKeyset(users_[0].obfuscated,
                                         std::move(key_blobs_), kPasswordLabel);
  ASSERT_THAT(vk_status, IsOk());

  ASSERT_THAT(keyset_management_->AddKeyset(
                  VaultKeysetIntent{.backup = false}, users_[0].obfuscated,
                  new_data.label(), new_data, *vk_status.value(),
                  std::move(new_key_blobs), std::move(auth_state), false),
              IsOk());

  // VERIFY
  // After we add an additional keyset, we can list and read both of them.
  vk_status =
      keyset_management_->GetVaultKeyset(users_[0].obfuscated, kNewLabel);
  ASSERT_THAT(vk_status, IsOk());
  int index = vk_status.value()->GetLegacyIndex();
  VerifyKeysetIndicies({kInitialKeysetIndex, index});

  VerifyWrappedKeysetPresentAtIndex(users_[0].obfuscated, kInitialBlob32,
                                    kInitialBlob16, kInitialBlob16,
                                    kPasswordLabel, kInitialKeysetIndex);
  VerifyWrappedKeysetPresentAtIndex(users_[0].obfuscated, kAdditionalBlob32,
                                    kAdditionalBlob16, kAdditionalBlob16,
                                    kNewLabel, index);
}

// Overrides existing keyset on label collision when "clobber" flag is present.
TEST_F(KeysetManagementTest, AddKeysetClobberSuccess) {
  // SETUP

  KeysetSetUpWithKeyDataAndKeyBlobs(DefaultKeyData());

  MountStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
      keyset_management_->GetValidKeyset(users_[0].obfuscated,
                                         std::move(key_blobs_), kPasswordLabel);
  ASSERT_THAT(vk_status, IsOk());

  // Re-use key data from existing credentials to cause label collision.
  KeyData new_key_data = DefaultKeyData();

  KeyBlobs new_key_blobs;
  new_key_blobs.vkk_key = kAdditionalBlob32;
  new_key_blobs.vkk_iv = kAdditionalBlob16;
  new_key_blobs.chaps_iv = kAdditionalBlob16;

  TpmBoundToPcrAuthBlockState pcr_state = {.salt = brillo::SecureBlob(kSalt)};
  auto auth_state = std::make_unique<AuthBlockState>();
  auth_state->state = pcr_state;
  // TEST

  ASSERT_THAT(
      keyset_management_->AddKeyset(
          VaultKeysetIntent{.backup = false}, users_[0].obfuscated,
          new_key_data.label(), new_key_data, *vk_status.value(),
          std::move(new_key_blobs), std::move(auth_state), true /*clobber*/),
      IsOk());

  // VERIFY
  // After we add an additional keyset, we can list and read both of them.

  VerifyKeysetIndicies({kInitialKeysetIndex});

  VerifyWrappedKeysetNotPresent(users_[0].obfuscated, kInitialBlob32,
                                kInitialBlob16, kInitialBlob16, kPasswordLabel);
  VerifyWrappedKeysetPresentAtIndex(users_[0].obfuscated, kAdditionalBlob32,
                                    kAdditionalBlob16, kAdditionalBlob16,
                                    kPasswordLabel, kInitialKeysetIndex);
}

// Return error on label collision when no "clobber".
TEST_F(KeysetManagementTest, AddKeysetNoClobber) {
  // SETUP

  KeysetSetUpWithKeyDataAndKeyBlobs(DefaultKeyData());

  // Re-use key data from existing credentials to cause label collision.
  KeyData new_key_data = DefaultKeyData();

  KeyBlobs new_key_blobs;
  new_key_blobs.vkk_key = kAdditionalBlob32;
  new_key_blobs.vkk_iv = kAdditionalBlob16;
  new_key_blobs.chaps_iv = kAdditionalBlob16;

  TpmBoundToPcrAuthBlockState pcr_state = {.salt = brillo::SecureBlob(kSalt)};
  auto auth_state = std::make_unique<AuthBlockState>();
  auth_state->state = pcr_state;
  // TEST
  MountStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
      keyset_management_->GetValidKeyset(users_[0].obfuscated,
                                         std::move(key_blobs_), kPasswordLabel);
  ASSERT_THAT(vk_status, IsOk());

  CryptohomeStatus status = keyset_management_->AddKeyset(
      VaultKeysetIntent{.backup = false}, users_[0].obfuscated,
      new_key_data.label(), new_key_data, *vk_status.value(),
      std::move(new_key_blobs), std::move(auth_state), false /*clobber*/);
  ASSERT_THAT(status, NotOk());
  ASSERT_EQ(status.status()->local_legacy_error(),
            CRYPTOHOME_ERROR_KEY_LABEL_EXISTS);

  // VERIFY
  // After we add an additional keyset, we can list and read both of them.
  VerifyKeysetIndicies({kInitialKeysetIndex});

  VerifyWrappedKeysetPresentAtIndex(users_[0].obfuscated, kInitialBlob32,
                                    kInitialBlob16, kInitialBlob16,
                                    kPasswordLabel, kInitialKeysetIndex);
  VerifyWrappedKeysetNotPresent(users_[0].obfuscated, kAdditionalBlob32,
                                kAdditionalBlob16, kAdditionalBlob16,
                                kPasswordLabel);
}

// Fail to get keyset due to invalid label.
TEST_F(KeysetManagementTest, GetValidKeysetNonExistentLabel) {
  // SETUP
  KeysetSetUpWithKeyDataAndKeyBlobs(DefaultKeyData());

  // TEST

  MountStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
      keyset_management_->GetValidKeyset(
          users_[0].obfuscated, std::move(key_blobs_), kNewLabel /*label*/);
  ASSERT_THAT(vk_status, NotOk());
  EXPECT_EQ(vk_status.status()->mount_error(),
            MountError::MOUNT_ERROR_KEY_FAILURE);
}

// Fail to get keyset due to invalid key blobs.
TEST_F(KeysetManagementTest, GetValidKeysetInvalidKeyBlobs) {
  // SETUP

  KeysetSetUpWithKeyDataAndKeyBlobs(DefaultKeyData());

  KeyBlobs wrong_key_blobs;
  wrong_key_blobs.vkk_key = kAdditionalBlob32;
  wrong_key_blobs.vkk_iv = kAdditionalBlob16;
  wrong_key_blobs.chaps_iv = kAdditionalBlob16;

  // TEST

  MountStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
      keyset_management_->GetValidKeyset(
          users_[0].obfuscated, std::move(wrong_key_blobs), kPasswordLabel);
  ASSERT_THAT(vk_status, NotOk());
  EXPECT_EQ(vk_status.status()->mount_error(),
            MountError::MOUNT_ERROR_KEY_FAILURE);
}

// Fail to add new keyset due to file name index pool exhaustion.
TEST_F(KeysetManagementTest, AddKeysetNoFreeIndices) {
  // SETUP

  KeysetSetUpWithKeyDataAndKeyBlobs(DefaultKeyData());

  KeyData new_data;
  new_data.set_label(kNewLabel);
  KeyBlobs new_key_blobs;
  new_key_blobs.vkk_key = kAdditionalBlob32;
  new_key_blobs.vkk_iv = kAdditionalBlob16;
  new_key_blobs.chaps_iv = kAdditionalBlob16;

  // Use mock not to literally create a hundread files.
  EXPECT_CALL(platform_,
              OpenFile(Property(&base::FilePath::value,
                                MatchesRegex(".*/master\\..*$")),  // nocheck
                       StrEq("wx")))
      .WillRepeatedly(Return(nullptr));

  // TEST
  MountStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
      keyset_management_->GetValidKeyset(users_[0].obfuscated,
                                         std::move(key_blobs_), kPasswordLabel);
  ASSERT_THAT(vk_status, IsOk());
  CryptohomeStatus status = keyset_management_->AddKeyset(
      VaultKeysetIntent{.backup = false}, users_[0].obfuscated,
      new_data.label(), new_data, *vk_status.value(), std::move(new_key_blobs),
      std::move(auth_state_), false /*clobber*/);
  ASSERT_THAT(status, NotOk());
  ASSERT_EQ(status.status()->local_legacy_error(),
            CRYPTOHOME_ERROR_KEY_QUOTA_EXCEEDED);

  // VERIFY
  // Nothing should change if we were not able to add keyset due to a lack
  // of free slots. Since we mocked the "slot" check, we should still have
  // only initial keyset index, adn the keyset is readable with the old
  // credentials.

  VerifyKeysetIndicies({kInitialKeysetIndex});

  VerifyWrappedKeysetPresentAtIndex(users_[0].obfuscated, kInitialBlob32,
                                    kInitialBlob16, kInitialBlob16,
                                    kPasswordLabel, kInitialKeysetIndex);
  VerifyWrappedKeysetNotPresent(users_[0].obfuscated, kAdditionalBlob32,
                                kAdditionalBlob16, kAdditionalBlob16,
                                new_data.label());
}

// Fail to add new keyset due to failed encryption.
TEST_F(KeysetManagementTest, AddKeysetEncryptFail) {
  // SETUP

  KeysetSetUpWithoutKeyDataAndKeyBlobs();

  KeyData new_data;
  new_data.set_label(kNewLabel);

  // To fail Encrypt() vkk_iv is missing in the key blobs.
  KeyBlobs new_key_blobs;
  new_key_blobs.vkk_key = kAdditionalBlob32;
  new_key_blobs.chaps_iv = kAdditionalBlob16;

  MountStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
      keyset_management_->GetValidKeyset(users_[0].obfuscated,
                                         std::move(key_blobs_), "" /*label*/);
  ASSERT_THAT(vk_status, IsOk());

  // TEST
  CryptohomeStatus status = keyset_management_->AddKeyset(
      VaultKeysetIntent{.backup = false}, users_[0].obfuscated,
      new_data.label(), new_data, *vk_status.value(), std::move(new_key_blobs),
      std::move(auth_state_), false /*clobber*/);
  ASSERT_THAT(status, NotOk());
  ASSERT_EQ(status.status()->local_legacy_error(),
            CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);

  // VERIFY
  // If we failed to save the added keyset due to disk failure, the old
  // keyset should still exist and be readable with the old key_blobs.

  VerifyKeysetIndicies({kInitialKeysetIndex});

  VerifyWrappedKeysetPresentAtIndex(users_[0].obfuscated, kInitialBlob32,
                                    kInitialBlob16, kInitialBlob16,
                                    "" /*label*/, kInitialKeysetIndex);
  VerifyWrappedKeysetNotPresent(users_[0].obfuscated, kAdditionalBlob32,
                                kAdditionalBlob16, kAdditionalBlob16,
                                new_data.label());
}

// Successfully adds initial keyset
TEST_F(KeysetManagementTest, AddInitialKeyset) {
  // SETUP
  key_blobs_ = {.vkk_key = kInitialBlob32,
                .vkk_iv = kInitialBlob16,
                .chaps_iv = kInitialBlob16};

  TpmBoundToPcrAuthBlockState pcr_state = {.salt = brillo::SecureBlob(kSalt)};
  auth_state_ = std::make_unique<AuthBlockState>();
  auth_state_->state = pcr_state;
  users_[0].key_data = DefaultKeyData();

  // TEST
  EXPECT_TRUE(
      keyset_management_
          ->AddInitialKeyset(VaultKeysetIntent{.backup = false},
                             users_[0].obfuscated, users_[0].key_data,
                             users_[0].challenge_credentials_keyset_info,
                             file_system_keyset_, std::move(key_blobs_),
                             std::move(auth_state_))
          .ok());

  // VERIFY

  VerifyWrappedKeysetPresentAtIndex(users_[0].obfuscated, kInitialBlob32,
                                    kInitialBlob16, kInitialBlob16,
                                    "" /*label*/, kInitialKeysetIndex);
}

// Tests whether AddResetSeedIfMissing() adds a reset seed to the input
// vault keyset when missing.
TEST_F(KeysetManagementTest, AddResetSeed) {
  // Setup a vault keyset.
  //
  // Non-scrypt encryption would fail on missing reset seed, so use scrypt.
  VaultKeyset vk;
  vk.Initialize(&platform_, &crypto_);
  vk.CreateFromFileSystemKeyset(file_system_keyset_);
  vk.SetKeyData(DefaultKeyData());

  key_blobs_.vkk_key = brillo::SecureBlob(kInitialBlob64 /*derived_key*/);
  key_blobs_.scrypt_chaps_key =
      brillo::SecureBlob(kInitialBlob64 /*derived_key*/);
  key_blobs_.scrypt_reset_seed_key =
      brillo::SecureBlob(kInitialBlob64 /*derived_key*/);
  ScryptAuthBlockState scrypt_state = {.salt = kInitialBlob32,
                                       .chaps_salt = kInitialBlob32,
                                       .reset_seed_salt = kInitialBlob32};
  auth_state_->state = scrypt_state;

  // Explicitly set |reset_seed_| to be empty.
  vk.reset_seed_.clear();
  ASSERT_THAT(vk.EncryptEx(key_blobs_, *auth_state_), IsOk());
  ASSERT_TRUE(
      vk.Save(users_[0].homedir_path.Append(kKeyFile).AddExtension("0")));

  MountStatusOr<std::unique_ptr<VaultKeyset>> init_vk_status =
      keyset_management_->GetValidKeyset(users_[0].obfuscated,
                                         std::move(key_blobs_), kPasswordLabel);
  ASSERT_THAT(init_vk_status, IsOk());
  EXPECT_FALSE(init_vk_status.value()->HasWrappedResetSeed());
  // Generate reset seed and add it to the VaultKeyset object. Need to generate
  // the Keyblobs again since it is not available any more.
  KeyBlobs key_blobs = {
      .vkk_key = brillo::SecureBlob(kInitialBlob64 /*derived_key*/),
      .scrypt_chaps_key = brillo::SecureBlob(kInitialBlob64 /*derived_key*/),
      .scrypt_reset_seed_key =
          brillo::SecureBlob(kInitialBlob64 /*derived_key*/)};
  // Test
  EXPECT_TRUE(
      keyset_management_->AddResetSeedIfMissing(*init_vk_status.value()));
  EXPECT_THAT(keyset_management_->EncryptAndSaveKeyset(
                  *init_vk_status.value(), key_blobs, *auth_state_,
                  users_[0].homedir_path.Append(kKeyFile).AddExtension("0")),
              IsOk());

  // Verify
  EXPECT_TRUE(init_vk_status.value()->HasWrappedResetSeed());
}

}  // namespace cryptohome
