// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for RealUserSession.

#include "cryptohome/user_session/real_user_session.h"

#include <memory>
#include <string>
#include <vector>

#include <base/memory/ref_counted.h>
#include <base/test/task_environment.h>
#include <brillo/cryptohome.h>
#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec/frontend/cryptohome/mock_frontend.h>
#include <libhwsec/frontend/pinweaver/mock_frontend.h>
#include <libhwsec-foundation/crypto/hmac.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <policy/libpolicy.h>
#include <policy/mock_device_policy.h>

#include "cryptohome/crypto.h"
#include "cryptohome/filesystem_layout.h"
#include "cryptohome/keyset_management.h"
#include "cryptohome/mock_credential_verifier.h"
#include "cryptohome/mock_cryptohome_keys_manager.h"
#include "cryptohome/mock_platform.h"
#include "cryptohome/pkcs11/fake_pkcs11_token.h"
#include "cryptohome/pkcs11/mock_pkcs11_token_factory.h"
#include "cryptohome/storage/file_system_keyset.h"
#include "cryptohome/storage/homedirs.h"
#include "cryptohome/storage/mock_mount.h"

namespace cryptohome {

namespace {

using brillo::SecureBlob;
using brillo::cryptohome::home::SanitizeUserName;
using hwsec_foundation::HmacSha256;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnOk;

using ::testing::_;
using ::testing::ByRef;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Invoke;
using ::testing::IsEmpty;
using ::testing::IsFalse;
using ::testing::IsNull;
using ::testing::IsTrue;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::UnorderedElementsAre;

constexpr char kUser0[] = "First User";
constexpr char kUserPassword0[] = "user0_pass";
constexpr char kWebAuthnSecretHmacMessage[] = "AuthTimeWebAuthnSecret";
constexpr char kHibernateSecretHmacMessage[] = "AuthTimeHibernateSecret";

// Helper utility for making a stub verifier with a given label. Returns a
// "unique_ptr, ptr" pair so that tests that need to hand over ownership but
// hold on to a pointer can easily do so. Usually used as:
//
//   auto [verifier, ptr] = MakeTestVerifier("label")
std::pair<std::unique_ptr<CredentialVerifier>, CredentialVerifier*>
MakeTestVerifier(std::string label) {
  auto owned_ptr = std::make_unique<MockCredentialVerifier>(
      AuthFactorType::kPassword, std::move(label),
      AuthFactorMetadata{.metadata = auth_factor::PasswordMetadata()});
  auto* unowned_ptr = owned_ptr.get();
  return {std::move(owned_ptr), unowned_ptr};
}

}  // namespace

class RealUserSessionTest : public ::testing::Test {
 public:
  RealUserSessionTest()
      : crypto_(&hwsec_, &pinweaver_, &cryptohome_keys_manager_, nullptr) {}

  // Not copyable or movable
  RealUserSessionTest(const RealUserSessionTest&) = delete;
  RealUserSessionTest& operator=(const RealUserSessionTest&) = delete;
  RealUserSessionTest(RealUserSessionTest&&) = delete;
  RealUserSessionTest& operator=(RealUserSessionTest&&) = delete;

  void SetUp() override {
    keyset_management_ = std::make_unique<KeysetManagement>(
        &platform_, &crypto_, std::make_unique<VaultKeysetFactory>());
    user_activity_timestamp_manager_ =
        std::make_unique<UserOldestActivityTimestampManager>(&platform_);
    HomeDirs::RemoveCallback remove_callback;
    mock_device_policy_ = new policy::MockDevicePolicy();
    homedirs_ = std::make_unique<HomeDirs>(
        &platform_,
        std::make_unique<policy::PolicyProvider>(
            std::unique_ptr<policy::MockDevicePolicy>(mock_device_policy_)),
        remove_callback,
        /*vault_factory=*/nullptr);

    AddUser(kUser0, kUserPassword0);

    PrepareDirectoryStructure();

    homedirs_->Create(Username(kUser0));
    users_[0].user_fs_keyset = FileSystemKeyset::CreateRandom();

    mount_ = new NiceMock<MockMount>();

    ON_CALL(pkcs11_token_factory_, New(_, _, _))
        .WillByDefault(
            Invoke([](const Username& username, const base::FilePath& token_dir,
                      const brillo::SecureBlob& auth_data) {
              return std::make_unique<FakePkcs11Token>();
            }));

    session_ = std::make_unique<RealUserSession>(
        Username(kUser0), homedirs_.get(), keyset_management_.get(),
        user_activity_timestamp_manager_.get(), &pkcs11_token_factory_, mount_);
  }

 protected:
  struct UserInfo {
    Username name;
    ObfuscatedUsername obfuscated;
    brillo::SecureBlob passkey;
    base::FilePath homedir_path;
    base::FilePath user_path;
    FileSystemKeyset user_fs_keyset;
  };

  // Information about users' homedirs. The order of users is equal to kUsers.
  std::vector<UserInfo> users_;
  NiceMock<hwsec::MockCryptohomeFrontend> hwsec_;
  NiceMock<hwsec::MockPinWeaverFrontend> pinweaver_;
  NiceMock<MockPlatform> platform_;
  NiceMock<MockCryptohomeKeysManager> cryptohome_keys_manager_;
  NiceMock<MockPkcs11TokenFactory> pkcs11_token_factory_;
  Crypto crypto_;
  std::unique_ptr<KeysetManagement> keyset_management_;
  policy::MockDevicePolicy* mock_device_policy_;  // owned by homedirs_
  std::unique_ptr<UserOldestActivityTimestampManager>
      user_activity_timestamp_manager_;
  std::unique_ptr<HomeDirs> homedirs_;
  std::unique_ptr<RealUserSession> session_;
  // TODO(dlunev): Replace with real mount when FakePlatform is mature enough
  // to support it mock-less.
  scoped_refptr<MockMount> mount_;
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

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
  }

  void PreparePolicy(bool enterprise_owned, const std::string& owner) {
    homedirs_->set_enterprise_owned(enterprise_owned);
    EXPECT_CALL(*mock_device_policy_,
                LoadPolicy(/*delete_invalid_files=*/false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_device_policy_, GetOwner(_))
        .WillRepeatedly(DoAll(SetArgPointee<0>(owner), Return(!owner.empty())));
  }
};

MATCHER_P(VaultOptionsEqual, options, "") {
  return arg.force_type == options.force_type &&
         arg.migrate == options.migrate &&
         arg.block_ecryptfs == options.block_ecryptfs;
}

// Mount twice: first time with create, and the second time for the existing
// one.
TEST_F(RealUserSessionTest, MountVaultOk) {
  // SETUP

  const base::Time kTs1 = base::Time::FromInternalValue(42);
  const base::Time kTs2 = base::Time::FromInternalValue(43);
  const base::Time kTs3 = base::Time::FromInternalValue(44);

  // Test with ecryptfs since it has a simpler existence check.
  CryptohomeVault::Options options = {
      .force_type = EncryptedContainerType::kEcryptfs,
  };

  // Set the credentials with |users_[0].credentials| so that
  // |obfuscated_username_| is explicitly set during the Unmount test.
  FileSystemKeyset fs_keyset = users_[0].user_fs_keyset;
  EXPECT_CALL(*mount_,
              MountCryptohome(users_[0].name, _, VaultOptionsEqual(options)))
      .WillOnce(ReturnOk<StorageError>());
  EXPECT_CALL(platform_, GetCurrentTime()).WillOnce(Return(kTs1));
  EXPECT_CALL(pkcs11_token_factory_, New(users_[0].name, _, _))
      .RetiresOnSaturation();

  // TEST

  EXPECT_TRUE(session_->MountVault(users_[0].name, fs_keyset, options).ok());

  // VERIFY
  // Vault created.
  EXPECT_THAT(user_activity_timestamp_manager_->GetLastUserActivityTimestamp(
                  users_[0].obfuscated),
              Eq(kTs1));

  // The WebAuthn secret isn't stored when mounting.
  EXPECT_EQ(session_->GetWebAuthnSecret(), nullptr);
  EXPECT_FALSE(session_->GetWebAuthnSecretHash().empty());
  EXPECT_NE(session_->GetHibernateSecret(), nullptr);

  EXPECT_NE(session_->GetPkcs11Token(), nullptr);
  ASSERT_FALSE(session_->GetPkcs11Token()->IsReady());
  ASSERT_TRUE(session_->GetPkcs11Token()->Insert());
  ASSERT_TRUE(session_->GetPkcs11Token()->IsReady());

  // SETUP

  // TODO(dlunev): this is required to mimic a real Mount::PrepareCryptohome
  // call. Remove it when we are not mocking mount.
  platform_.CreateDirectory(GetEcryptfsUserVaultPath(users_[0].obfuscated));

  // Mount args with no create.
  options = {};

  // Set the credentials with |users_[0].credentials| so that
  // |obfuscated_username_| is explicitly set during the Unmount test.
  EXPECT_CALL(*mount_,
              MountCryptohome(users_[0].name, _, VaultOptionsEqual(options)))
      .WillOnce(ReturnOk<StorageError>());
  EXPECT_CALL(platform_, GetCurrentTime()).WillOnce(Return(kTs2));
  EXPECT_CALL(pkcs11_token_factory_, New(users_[0].name, _, _))
      .RetiresOnSaturation();

  // TEST

  EXPECT_TRUE(session_->MountVault(users_[0].name, fs_keyset, options).ok());

  // VERIFY
  // Vault still exists when tried to remount with no create.
  // ts updated on mount
  EXPECT_TRUE(platform_.DirectoryExists(users_[0].homedir_path));
  EXPECT_THAT(user_activity_timestamp_manager_->GetLastUserActivityTimestamp(
                  users_[0].obfuscated),
              Eq(kTs2));

  ASSERT_FALSE(session_->GetPkcs11Token()->IsReady());
  ASSERT_TRUE(session_->GetPkcs11Token()->Insert());
  ASSERT_TRUE(session_->GetPkcs11Token()->IsReady());

  // SETUP
  // Set the credentials with |users_[0].credentials| so that
  // |obfuscated_username_| is explicitly set during the Unmount test.
  EXPECT_CALL(*mount_, IsNonEphemeralMounted()).WillOnce(Return(true));
  EXPECT_CALL(platform_, GetCurrentTime()).WillOnce(Return(kTs3));
  EXPECT_CALL(*mount_, UnmountCryptohome()).WillOnce(Return(true));

  // TEST

  ASSERT_TRUE(session_->Unmount());

  // VERIFY
  // ts updated on unmount
  EXPECT_THAT(user_activity_timestamp_manager_->GetLastUserActivityTimestamp(
                  users_[0].obfuscated),
              Eq(kTs3));
  EXPECT_EQ(session_->GetPkcs11Token(), nullptr);
}

TEST_F(RealUserSessionTest, EphemeralMountPolicyTest) {
  EXPECT_CALL(*mount_, MountEphemeralCryptohome(_))
      .WillRepeatedly(ReturnOk<StorageError>());

  struct PolicyTestCase {
    std::string name;
    bool is_enterprise;
    std::string owner;
    Username user;
    bool ok;
    MountError expected_result;
  };

  std::vector<PolicyTestCase> test_cases{
      {
          .name = "NotEnterprise_NoOwner_UserLogin_OK",
          .is_enterprise = false,
          .owner = "",
          .user = Username("some_user"),
          .ok = false,
          .expected_result = MOUNT_ERROR_EPHEMERAL_MOUNT_BY_OWNER,
      },
      {
          .name = "NotEnterprise_Owner_UserLogin_OK",
          .is_enterprise = false,
          .owner = "owner",
          .user = Username("some_user"),
          .ok = true,
      },
      {
          .name = "NotEnterprise_Owner_OwnerLogin_Error",
          .is_enterprise = false,
          .owner = "owner",
          .user = Username("owner"),
          .ok = false,
          .expected_result = MOUNT_ERROR_EPHEMERAL_MOUNT_BY_OWNER,
      },
      {
          .name = "Enterprise_NoOwner_UserLogin_OK",
          .is_enterprise = true,
          .owner = "",
          .user = Username("some_user"),
          .ok = true,
      },
      {
          .name = "Enterprise_Owner_UserLogin_OK",
          .is_enterprise = true,
          .owner = "owner",
          .user = Username("some_user"),
          .ok = true,
      },
      {
          .name = "Enterprise_Owner_OwnerLogin_OK",
          .is_enterprise = true,
          .owner = "owner",
          .user = Username("owner"),
          .ok = true,
      },
  };

  for (const auto& test_case : test_cases) {
    RealUserSession local_session(
        test_case.user, homedirs_.get(), keyset_management_.get(),
        user_activity_timestamp_manager_.get(), &pkcs11_token_factory_, mount_);
    if (test_case.ok) {
      // If the mount succeeds in the test, a PKCS11 token should be created.
      EXPECT_CALL(pkcs11_token_factory_, New(test_case.user, _, _))
          .RetiresOnSaturation();
    }

    PreparePolicy(test_case.is_enterprise, test_case.owner);
    MountStatus status = local_session.MountEphemeral(test_case.user);
    ASSERT_EQ(status.ok(), test_case.ok) << "Test case: " << test_case.name;
    if (!test_case.ok) {
      ASSERT_EQ(status->mount_error(), test_case.expected_result)
          << "Test case: " << test_case.name;
    }
  }
}

// WebAuthn secret and hibernate secrets are cleared after being read once.
TEST_F(RealUserSessionTest, WebAuthnAndHibernateSecretReadTwice) {
  // SETUP
  // Test with ecryptfs since it has a simpler existence check.
  CryptohomeVault::Options options = {
      .force_type = EncryptedContainerType::kEcryptfs,
  };

  FileSystemKeyset fs_keyset = users_[0].user_fs_keyset;
  EXPECT_CALL(*mount_,
              MountCryptohome(users_[0].name, _, VaultOptionsEqual(options)))
      .WillOnce(ReturnOk<StorageError>());

  EXPECT_TRUE(session_->MountVault(users_[0].name, fs_keyset, options).ok());
  const std::string message(kWebAuthnSecretHmacMessage);
  auto expected_webauthn_secret = std::make_unique<brillo::SecureBlob>(
      HmacSha256(brillo::SecureBlob::Combine(fs_keyset.Key().fnek,
                                             fs_keyset.Key().fek),
                 brillo::Blob(message.cbegin(), message.cend())));
  EXPECT_NE(expected_webauthn_secret, nullptr);
  const std::string hibernate_message(kHibernateSecretHmacMessage);
  auto expected_hibernate_secret =
      std::make_unique<brillo::SecureBlob>(HmacSha256(
          brillo::SecureBlob::Combine(fs_keyset.Key().fnek,
                                      fs_keyset.Key().fek),
          brillo::Blob(hibernate_message.cbegin(), hibernate_message.cend())));
  EXPECT_NE(expected_hibernate_secret, nullptr);

  // Call PrepareWebAuthnSecret because it isn't prepared when mounting.
  session_->PrepareWebAuthnSecret(fs_keyset.Key().fek, fs_keyset.Key().fnek);

  // TEST

  std::unique_ptr<brillo::SecureBlob> actual_webauthn_secret =
      session_->GetWebAuthnSecret();
  EXPECT_NE(actual_webauthn_secret, nullptr);
  EXPECT_EQ(*actual_webauthn_secret, *expected_webauthn_secret);
  std::unique_ptr<brillo::SecureBlob> actual_hibernate_secret =
      session_->GetHibernateSecret();
  EXPECT_NE(actual_hibernate_secret, nullptr);
  EXPECT_EQ(*actual_hibernate_secret, *expected_hibernate_secret);
  EXPECT_FALSE(session_->GetWebAuthnSecretHash().empty());
  // VERIFY

  // The second read should get nothing.
  EXPECT_EQ(session_->GetWebAuthnSecret(), nullptr);
  EXPECT_EQ(session_->GetHibernateSecret(), nullptr);

  // The second read of the WebAuthn secret hash should still get the hash.
  EXPECT_FALSE(session_->GetWebAuthnSecretHash().empty());
}

// Check whether Hibernate secret, WebAuthn secret and its hash exist at correct
// timing.
TEST_F(RealUserSessionTest, SecretsTimeout) {
  // SETUP

  // Test with ecryptfs since it has a simpler existence check.
  CryptohomeVault::Options options = {
      .force_type = EncryptedContainerType::kEcryptfs,
  };

  EXPECT_CALL(*mount_,
              MountCryptohome(users_[0].name, _, VaultOptionsEqual(options)))
      .WillOnce(ReturnOk<StorageError>());

  FileSystemKeyset fs_keyset = users_[0].user_fs_keyset;
  EXPECT_TRUE(session_->MountVault(users_[0].name, fs_keyset, options).ok());

  // The WebAuthn secret isn't stored when mounting.
  EXPECT_EQ(session_->GetWebAuthnSecret(), nullptr);

  session_->PrepareWebAuthnSecret(fs_keyset.Key().fek, fs_keyset.Key().fnek);
  EXPECT_NE(session_->GetWebAuthnSecret(), nullptr);

  task_environment_.FastForwardBy(base::Seconds(600));

  EXPECT_EQ(session_->GetWebAuthnSecret(), nullptr);
  EXPECT_EQ(session_->GetHibernateSecret(), nullptr);

  // The WebAuthn secret hash will not be cleared after timeout.
  EXPECT_FALSE(session_->GetWebAuthnSecretHash().empty());
}

class RealUserSessionReAuthTest : public ::testing::Test {
 public:
  // MockPlatform will provide environment with system salt.
  MockPlatform platform_;
  const Username kFakeUsername{"test_username"};
};

TEST_F(RealUserSessionReAuthTest, VerifyUser) {
  RealUserSession session(kFakeUsername, nullptr, nullptr, nullptr, nullptr,
                          nullptr);

  EXPECT_TRUE(session.VerifyUser(
      brillo::cryptohome::home::SanitizeUserName(kFakeUsername)));
  EXPECT_FALSE(session.VerifyUser(ObfuscatedUsername("other")));
}

TEST_F(RealUserSessionReAuthTest, AddAndRemoveCredentialVerifiers) {
  auto [verifier1, ptr1] = MakeTestVerifier("a1");
  auto [verifier2, ptr2] = MakeTestVerifier("b2");
  auto [verifier3, ptr3] = MakeTestVerifier("c3");

  RealUserSession session(kFakeUsername, nullptr, nullptr, nullptr, nullptr,
                          nullptr);

  // The session should start without verifiers.
  EXPECT_THAT(session.GetCredentialVerifiers(), IsEmpty());
  EXPECT_THAT(session.HasCredentialVerifier("a1"), IsFalse());
  EXPECT_THAT(session.FindCredentialVerifier("a1"), IsNull());

  // If we add a verifier it should show up.
  session.AddCredentialVerifier(std::move(verifier1));
  EXPECT_THAT(session.GetCredentialVerifiers(), UnorderedElementsAre(ptr1));
  EXPECT_THAT(session.HasCredentialVerifier("a1"), IsTrue());
  EXPECT_THAT(session.FindCredentialVerifier("a1"), Eq(ptr1));
  session.AddCredentialVerifier(std::move(verifier2));
  session.AddCredentialVerifier(std::move(verifier3));
  EXPECT_THAT(session.GetCredentialVerifiers(),
              UnorderedElementsAre(ptr1, ptr2, ptr3));

  // Finding the verifier by type should NOT work, since that should only find
  // label-less verifiers.
  EXPECT_THAT(session.HasCredentialVerifier(AuthFactorType::kPassword),
              IsFalse());
  EXPECT_THAT(session.FindCredentialVerifier(AuthFactorType::kPassword),
              IsNull());

  // If we remove a verifier it should disappear.
  session.RemoveCredentialVerifier("a1");
  EXPECT_THAT(session.GetCredentialVerifiers(),
              UnorderedElementsAre(ptr2, ptr3));
  EXPECT_THAT(session.HasCredentialVerifier("a1"), IsFalse());
  EXPECT_THAT(session.FindCredentialVerifier("a1"), IsNull());
}

TEST_F(RealUserSessionReAuthTest, AddAndRemoveLabellessCredentialVerifiers) {
  auto [verifier1, ptr1] = MakeTestVerifier("a1");
  auto [verifier2, ptr2] = MakeTestVerifier("b2");
  auto [verifier3, ptr3] = MakeTestVerifier("");  // label-less

  RealUserSession session(kFakeUsername, nullptr, nullptr, nullptr, nullptr,
                          nullptr);

  // The session should start without verifiers.
  EXPECT_THAT(session.GetCredentialVerifiers(), IsEmpty());
  EXPECT_THAT(session.HasCredentialVerifier(AuthFactorType::kPassword),
              IsFalse());
  EXPECT_THAT(session.FindCredentialVerifier(AuthFactorType::kPassword),
              IsNull());

  // If we add a label-less verifier it should show up. Note that it should NOT
  // show up if we search for a verifier with a blank label.
  session.AddCredentialVerifier(std::move(verifier3));
  EXPECT_THAT(session.GetCredentialVerifiers(), UnorderedElementsAre(ptr3));
  EXPECT_THAT(session.HasCredentialVerifier(AuthFactorType::kPassword),
              IsTrue());
  EXPECT_THAT(session.FindCredentialVerifier(AuthFactorType::kPassword),
              Eq(ptr3));
  EXPECT_THAT(session.HasCredentialVerifier(""), IsFalse());
  EXPECT_THAT(session.FindCredentialVerifier(""), IsNull());

  // Add the rest of the verifiers.
  session.AddCredentialVerifier(std::move(verifier1));
  session.AddCredentialVerifier(std::move(verifier2));
  EXPECT_THAT(session.GetCredentialVerifiers(),
              UnorderedElementsAre(ptr1, ptr2, ptr3));

  // Trying to remove the verifier by removing a blank label should do nothing.
  session.RemoveCredentialVerifier("");
  EXPECT_THAT(session.HasCredentialVerifier(AuthFactorType::kPassword),
              IsTrue());
  EXPECT_THAT(session.FindCredentialVerifier(AuthFactorType::kPassword),
              Eq(ptr3));
  EXPECT_THAT(session.GetCredentialVerifiers(),
              UnorderedElementsAre(ptr1, ptr2, ptr3));

  // But if we remove the verifier by type it should disappear.
  session.RemoveCredentialVerifier(AuthFactorType::kPassword);
  EXPECT_THAT(session.GetCredentialVerifiers(),
              UnorderedElementsAre(ptr1, ptr2));
  EXPECT_THAT(session.HasCredentialVerifier(AuthFactorType::kPassword),
              IsFalse());
  EXPECT_THAT(session.FindCredentialVerifier(AuthFactorType::kPassword),
              IsNull());
}

}  // namespace cryptohome
