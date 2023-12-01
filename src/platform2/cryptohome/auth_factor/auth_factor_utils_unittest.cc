// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <absl/types/variant.h>
#include <base/test/scoped_chromeos_version_info.h>
#include <cryptohome/proto_bindings/auth_factor.pb.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <libhwsec/frontend/cryptohome/mock_frontend.h>
#include <libhwsec/frontend/pinweaver/mock_frontend.h>

#include "cryptohome/auth_blocks/mock_auth_block_utility.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_prepare_purpose.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_factor/auth_factor_utils.h"
#include "cryptohome/auth_factor_generated.h"
#include "cryptohome/fake_features.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"
#include "cryptohome/mock_keyset_management.h"
#include "cryptohome/mock_platform.h"
#include "cryptohome/user_secret_stash/user_secret_stash.h"

namespace cryptohome {
namespace {

using ::brillo::SecureBlob;
using ::brillo::cryptohome::home::SanitizeUserName;
using ::hwsec_foundation::error::testing::IsOk;
using ::testing::_;
using ::testing::DoAll;
using ::testing::IsEmpty;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrictMock;

constexpr char kLabel[] = "some-label";
constexpr char kChromeosVersion[] = "1.2.3_a_b_c";
constexpr char kChromeVersion[] = "1.2.3.4";

// A matcher for an AuthFactorMap element. This will check the type, label and
// storage type of the item. You generally want to combine this with
// UnorderedElementsAre to compare it against an entire AuthFactorMap, but you
// can also use it directly with individual elements in the map.
class AuthFactorMapItemMatcher
    : public ::testing::MatcherInterface<AuthFactorMap::ValueView> {
 public:
  AuthFactorMapItemMatcher(AuthFactorType type,
                           std::string label,
                           AuthFactorStorageType storage_type)
      : type_(type), label_(std::move(label)), storage_type_(storage_type) {}

  bool MatchAndExplain(
      AuthFactorMap::ValueView value,
      ::testing::MatchResultListener* listener) const override {
    bool matches = true;
    if (value.auth_factor().type() != type_) {
      matches = false;
      *listener << "type is: "
                << AuthFactorTypeToString(value.auth_factor().type()) << "\n";
    }
    if (value.auth_factor().label() != label_) {
      matches = false;
      *listener << "label is: " << value.auth_factor().label() << "\n";
    }
    if (value.storage_type() != storage_type_) {
      matches = false;
      *listener << "label is: "
                << AuthFactorStorageTypeToDebugString(value.storage_type())
                << "\n";
    }
    return matches;
  }

  void DescribeTo(std::ostream* os) const override {
    *os << "has type " << AuthFactorTypeToString(type_) << ", label " << label_
        << " and storage type "
        << AuthFactorStorageTypeToDebugString(storage_type_);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    *os << "does not have type " << AuthFactorTypeToString(type_)
        << " or does not have label " << label_
        << " or does not have storage type "
        << AuthFactorStorageTypeToDebugString(storage_type_);
  }

 private:
  AuthFactorType type_;
  std::string label_;
  AuthFactorStorageType storage_type_;
};
::testing::Matcher<AuthFactorMap::ValueView> AuthFactorMapItem(
    AuthFactorType type,
    std::string label,
    AuthFactorStorageType storage_type) {
  return ::testing::MakeMatcher<AuthFactorMap::ValueView>(
      new AuthFactorMapItemMatcher(type, std::move(label), storage_type));
}

std::unique_ptr<VaultKeyset> CreatePasswordVaultKeyset(
    const std::string& label) {
  SerializedVaultKeyset serialized_vk;
  serialized_vk.set_flags(SerializedVaultKeyset::TPM_WRAPPED |
                          SerializedVaultKeyset::SCRYPT_DERIVED |
                          SerializedVaultKeyset::PCR_BOUND |
                          SerializedVaultKeyset::ECC);
  serialized_vk.set_password_rounds(1);
  serialized_vk.set_tpm_key("tpm-key");
  serialized_vk.set_extended_tpm_key("tpm-extended-key");
  serialized_vk.set_vkk_iv("iv");
  serialized_vk.mutable_key_data()->set_type(KeyData::KEY_TYPE_PASSWORD);
  serialized_vk.mutable_key_data()->set_label(label);
  auto vk = std::make_unique<VaultKeyset>();
  vk->InitializeFromSerialized(serialized_vk);
  return vk;
}

std::unique_ptr<VaultKeyset> CreateBackupVaultKeyset(const std::string& label) {
  auto backup_vk = CreatePasswordVaultKeyset(label);
  backup_vk->set_backup_vk_for_testing(true);
  backup_vk->SetResetSeed(brillo::SecureBlob(32, 'A'));
  backup_vk->SetWrappedResetSeed(brillo::SecureBlob(32, 'B'));
  return backup_vk;
}

std::unique_ptr<VaultKeyset> CreateMigratedVaultKeyset(
    const std::string& label) {
  auto migrated_vk = CreateBackupVaultKeyset(label);
  migrated_vk->set_migrated_vk_for_testing(true);
  return migrated_vk;
}

TEST(AuthFactorUtilsTest, PopulateSysinfoWithOsVersion) {
  static constexpr char kLsbRelease[] =
      R"(CHROMEOS_RELEASE_NAME=Chrome OS
CHROMEOS_RELEASE_VERSION=11012.0.2018_08_28_1422
)";
  base::test::ScopedChromeOSVersionInfo scoped_version(
      kLsbRelease, /*lsb_release_time=*/base::Time());

  static constexpr char kLsbReleaseVersion[] = "11012.0.2018_08_28_1422";
  static constexpr char kOtherVersion[] = "11011.0.2017_07_27_1421";

  // Try filling in a blank proto.
  user_data_auth::AuthFactor auth_factor;
  PopulateAuthFactorProtoWithSysinfo(auth_factor);
  EXPECT_EQ(auth_factor.common_metadata().chromeos_version_last_updated(),
            kLsbReleaseVersion);

  // Try filling in a proto with existing data.
  user_data_auth::AuthFactor auth_factor_with_existing_data;
  auth_factor_with_existing_data.mutable_common_metadata()
      ->set_chromeos_version_last_updated(kOtherVersion);
  EXPECT_EQ(auth_factor_with_existing_data.common_metadata()
                .chromeos_version_last_updated(),
            kOtherVersion);
  PopulateAuthFactorProtoWithSysinfo(auth_factor_with_existing_data);
  EXPECT_EQ(auth_factor_with_existing_data.common_metadata()
                .chromeos_version_last_updated(),
            kLsbReleaseVersion);
}

TEST(AuthFactorUtilsTest, PopulateSysinfoWithOsVersionFails) {
  static constexpr char kLsbRelease[] =
      R"(CHROMEOS_RELEASE_NAME=Chrome OS
)";
  base::test::ScopedChromeOSVersionInfo scoped_version(
      kLsbRelease, /*lsb_release_time=*/base::Time());

  static constexpr char kVersion[] = "11011.0.2017_07_27_1421";

  // Try filling in a blank proto.
  user_data_auth::AuthFactor auth_factor;
  PopulateAuthFactorProtoWithSysinfo(auth_factor);
  EXPECT_EQ(auth_factor.common_metadata().chromeos_version_last_updated(), "");

  // Try filling in a proto with existing data.
  user_data_auth::AuthFactor auth_factor_with_existing_data;
  auth_factor_with_existing_data.mutable_common_metadata()
      ->set_chromeos_version_last_updated(kVersion);
  EXPECT_EQ(auth_factor_with_existing_data.common_metadata()
                .chromeos_version_last_updated(),
            kVersion);
  PopulateAuthFactorProtoWithSysinfo(auth_factor_with_existing_data);
  EXPECT_EQ(auth_factor_with_existing_data.common_metadata()
                .chromeos_version_last_updated(),
            "");
}

TEST(AuthFactorUtilsTest, AuthFactorMetaDataCheck) {
  // Setup
  user_data_auth::AuthFactor auth_factor_proto;
  auto& common_metadata_proto = *auth_factor_proto.mutable_common_metadata();
  common_metadata_proto.set_chromeos_version_last_updated(kChromeosVersion);
  common_metadata_proto.set_chrome_version_last_updated(kChromeVersion);
  auth_factor_proto.mutable_password_metadata();
  auth_factor_proto.set_type(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  auth_factor_proto.set_label(kLabel);

  // Test
  AuthFactorMetadata auth_factor_metadata;
  AuthFactorType auth_factor_type;
  std::string auth_factor_label;
  FakeFeaturesForTesting features;
  EXPECT_TRUE(GetAuthFactorMetadata(auth_factor_proto, features.async,
                                    auth_factor_metadata, auth_factor_type,
                                    auth_factor_label));

  // Verify
  EXPECT_EQ(auth_factor_metadata.common.chromeos_version_last_updated,
            kChromeosVersion);
  EXPECT_EQ(auth_factor_metadata.common.chrome_version_last_updated,
            kChromeVersion);
  EXPECT_EQ(auth_factor_metadata.common.lockout_policy,
            auth_factor::LockoutPolicy::NO_LOCKOUT);
  EXPECT_TRUE(absl::holds_alternative<auth_factor::PasswordMetadata>(
      auth_factor_metadata.metadata));
  EXPECT_EQ(auth_factor_type, AuthFactorType::kPassword);
  EXPECT_EQ(auth_factor_label, kLabel);
}

TEST(AuthFactorUtilsTest, AuthFactorMetaDataCheckPIN) {
  // Setup
  user_data_auth::AuthFactor auth_factor_proto;
  auto& common_metadata_proto = *auth_factor_proto.mutable_common_metadata();
  common_metadata_proto.set_chromeos_version_last_updated(kChromeosVersion);
  common_metadata_proto.set_chrome_version_last_updated(kChromeVersion);
  common_metadata_proto.set_lockout_policy(
      user_data_auth::LOCKOUT_POLICY_ATTEMPT_LIMITED);
  auth_factor_proto.mutable_pin_metadata();
  auth_factor_proto.set_type(user_data_auth::AUTH_FACTOR_TYPE_PIN);
  auth_factor_proto.set_label(kLabel);

  // Test
  AuthFactorMetadata auth_factor_metadata;
  AuthFactorType auth_factor_type;
  std::string auth_factor_label;
  FakeFeaturesForTesting features;
  EXPECT_TRUE(GetAuthFactorMetadata(auth_factor_proto, features.async,
                                    auth_factor_metadata, auth_factor_type,
                                    auth_factor_label));

  // Verify
  EXPECT_EQ(auth_factor_metadata.common.chromeos_version_last_updated,
            kChromeosVersion);
  EXPECT_EQ(auth_factor_metadata.common.chrome_version_last_updated,
            kChromeVersion);
  EXPECT_EQ(auth_factor_metadata.common.lockout_policy,
            auth_factor::LockoutPolicy::ATTEMPT_LIMITED);
  EXPECT_TRUE(absl::holds_alternative<auth_factor::PinMetadata>(
      auth_factor_metadata.metadata));
  EXPECT_EQ(auth_factor_type, AuthFactorType::kPin);
  EXPECT_EQ(auth_factor_label, kLabel);
}

TEST(AuthFactorUtilsTest, AuthFactorMetaDataCheckPINTimeLimit) {
  // Setup
  user_data_auth::AuthFactor auth_factor_proto;
  auto& common_metadata_proto = *auth_factor_proto.mutable_common_metadata();
  common_metadata_proto.set_chromeos_version_last_updated(kChromeosVersion);
  common_metadata_proto.set_chrome_version_last_updated(kChromeVersion);
  common_metadata_proto.set_lockout_policy(
      user_data_auth::LOCKOUT_POLICY_TIME_LIMITED);
  auth_factor_proto.mutable_pin_metadata();
  auth_factor_proto.set_type(user_data_auth::AUTH_FACTOR_TYPE_PIN);
  auth_factor_proto.set_label(kLabel);

  // Test
  AuthFactorMetadata auth_factor_metadata;
  AuthFactorType auth_factor_type;
  std::string auth_factor_label;
  FakeFeaturesForTesting features;
  EXPECT_TRUE(GetAuthFactorMetadata(auth_factor_proto, features.async,
                                    auth_factor_metadata, auth_factor_type,
                                    auth_factor_label));

  // Verify
  EXPECT_EQ(auth_factor_metadata.common.chromeos_version_last_updated,
            kChromeosVersion);
  EXPECT_EQ(auth_factor_metadata.common.chrome_version_last_updated,
            kChromeVersion);
  EXPECT_EQ(auth_factor_metadata.common.lockout_policy,
            auth_factor::LockoutPolicy::TIME_LIMITED);
  EXPECT_TRUE(absl::holds_alternative<auth_factor::PinMetadata>(
      auth_factor_metadata.metadata));
  EXPECT_EQ(auth_factor_type, AuthFactorType::kPin);
  EXPECT_EQ(auth_factor_label, kLabel);
}

TEST(AuthFactorUtilsTest, AuthFactorMetaDataCheckPINAttemptLimitFeaturesNull) {
  // Setup
  user_data_auth::AuthFactor auth_factor_proto;
  auto& common_metadata_proto = *auth_factor_proto.mutable_common_metadata();
  common_metadata_proto.set_chromeos_version_last_updated(kChromeosVersion);
  common_metadata_proto.set_chrome_version_last_updated(kChromeVersion);
  common_metadata_proto.set_lockout_policy(
      user_data_auth::LOCKOUT_POLICY_TIME_LIMITED);
  auth_factor_proto.mutable_pin_metadata();
  auth_factor_proto.set_type(user_data_auth::AUTH_FACTOR_TYPE_PIN);
  auth_factor_proto.set_label(kLabel);

  // Test
  AuthFactorMetadata auth_factor_metadata;
  AuthFactorType auth_factor_type;
  std::string auth_factor_label;
  FakeFeaturesForTesting features;
  EXPECT_TRUE(GetAuthFactorMetadata(auth_factor_proto, features.async,
                                    auth_factor_metadata, auth_factor_type,
                                    auth_factor_label));

  // Verify
  EXPECT_EQ(auth_factor_metadata.common.chromeos_version_last_updated,
            kChromeosVersion);
  EXPECT_EQ(auth_factor_metadata.common.chrome_version_last_updated,
            kChromeVersion);
  EXPECT_EQ(auth_factor_metadata.common.lockout_policy,
            auth_factor::LockoutPolicy::TIME_LIMITED);
  EXPECT_TRUE(absl::holds_alternative<auth_factor::PinMetadata>(
      auth_factor_metadata.metadata));
  EXPECT_EQ(auth_factor_type, AuthFactorType::kPin);
  EXPECT_EQ(auth_factor_label, kLabel);
}

TEST(AuthFactorUtilsTest,
     AuthFactorMetaDataCheckPINAttemptLimitFeatureEnabled) {
  // Setup
  user_data_auth::AuthFactor auth_factor_proto;
  auto& common_metadata_proto = *auth_factor_proto.mutable_common_metadata();
  common_metadata_proto.set_chromeos_version_last_updated(kChromeosVersion);
  common_metadata_proto.set_chrome_version_last_updated(kChromeVersion);
  common_metadata_proto.set_lockout_policy(
      user_data_auth::LOCKOUT_POLICY_TIME_LIMITED);
  auth_factor_proto.mutable_pin_metadata();
  auth_factor_proto.set_type(user_data_auth::AUTH_FACTOR_TYPE_PIN);
  auth_factor_proto.set_label(kLabel);

  // Test
  AuthFactorMetadata auth_factor_metadata;
  AuthFactorType auth_factor_type;
  std::string auth_factor_label;
  FakeFeaturesForTesting features;
  features.SetDefaultForFeature(Features::kModernPin, /*enabled=*/true);
  EXPECT_TRUE(GetAuthFactorMetadata(auth_factor_proto, features.async,
                                    auth_factor_metadata, auth_factor_type,
                                    auth_factor_label));

  // Verify
  EXPECT_EQ(auth_factor_metadata.common.chromeos_version_last_updated,
            kChromeosVersion);
  EXPECT_EQ(auth_factor_metadata.common.chrome_version_last_updated,
            kChromeVersion);
  EXPECT_EQ(auth_factor_metadata.common.lockout_policy,
            auth_factor::LockoutPolicy::TIME_LIMITED);
  EXPECT_TRUE(absl::holds_alternative<auth_factor::PinMetadata>(
      auth_factor_metadata.metadata));
  EXPECT_EQ(auth_factor_type, AuthFactorType::kPin);
  EXPECT_EQ(auth_factor_label, kLabel);
}

TEST(AuthFactorUtilsTest,
     AuthFactorMetaDataCheckPINAttemptLimitFeatureEnabledWrongInput) {
  // Setup
  user_data_auth::AuthFactor auth_factor_proto;
  auto& common_metadata_proto = *auth_factor_proto.mutable_common_metadata();
  common_metadata_proto.set_chromeos_version_last_updated(kChromeosVersion);
  common_metadata_proto.set_chrome_version_last_updated(kChromeVersion);
  common_metadata_proto.set_lockout_policy(
      user_data_auth::LOCKOUT_POLICY_ATTEMPT_LIMITED);
  auth_factor_proto.mutable_pin_metadata();
  auth_factor_proto.set_type(user_data_auth::AUTH_FACTOR_TYPE_PIN);
  auth_factor_proto.set_label(kLabel);

  // Test
  AuthFactorMetadata auth_factor_metadata;
  AuthFactorType auth_factor_type;
  std::string auth_factor_label;
  FakeFeaturesForTesting features;
  features.SetDefaultForFeature(Features::kModernPin, /*enabled=*/true);
  EXPECT_FALSE(GetAuthFactorMetadata(auth_factor_proto, features.async,
                                     auth_factor_metadata, auth_factor_type,
                                     auth_factor_label));
}

TEST(AuthSessionProtoUtils, AuthFactorPreparePurposeFromProto) {
  EXPECT_EQ(AuthFactorPreparePurposeFromProto(
                user_data_auth::PURPOSE_ADD_AUTH_FACTOR),
            AuthFactorPreparePurpose::kPrepareAddAuthFactor);
  EXPECT_EQ(AuthFactorPreparePurposeFromProto(
                user_data_auth::PURPOSE_AUTHENTICATE_AUTH_FACTOR),
            AuthFactorPreparePurpose::kPrepareAuthenticateAuthFactor);
  EXPECT_EQ(
      AuthFactorPreparePurposeFromProto(user_data_auth::PURPOSE_UNSPECIFIED),
      std::nullopt);
}

class LoadAuthFactorMapTest : public ::testing::Test {
 protected:
  // Install mocks to set up vault keysets for testing. Expects a map of VK
  // labels to factory functions that will construct a VaultKeyset object.
  void InstallVaultKeysets(
      std::map<std::string,
               std::unique_ptr<VaultKeyset> (*)(const std::string&)>
          vk_factory_map) {
    std::vector<int> key_indicies;
    for (const auto& [label, factory] : vk_factory_map) {
      int index = key_indicies.size();
      key_indicies.push_back(index);
      EXPECT_CALL(keyset_management_,
                  LoadVaultKeysetForUser(kObfuscatedUsername, index))
          .WillRepeatedly([label = label, factory = factory](auto...) {
            return factory(label);
          });
    }
    EXPECT_CALL(keyset_management_, GetVaultKeysets(kObfuscatedUsername, _))
        .WillRepeatedly(DoAll(SetArgPointee<1>(key_indicies), Return(true)));
  }

  // Install a single USS auth factor. If you want to set up multiple factors
  // for your test, call this multiple times.
  void InstallUssFactor(AuthFactor factor) {
    EXPECT_THAT(manager_.SaveAuthFactor(kObfuscatedUsername, factor), IsOk());
  }

  FakePlatform platform_;

  // Username used for all tests.
  const Username kUsername{"user@testing.com"};
  // Computing the obfuscated name requires the system salt from FakePlatform
  // and so this must be defined after it and not before.
  const ObfuscatedUsername kObfuscatedUsername{SanitizeUserName(kUsername)};

  StrictMock<MockKeysetManagement> keyset_management_;
  AuthFactorVaultKeysetConverter converter_{&keyset_management_};
  AuthFactorManager manager_{&platform_};
};

// Test that if nothing is set up, no factors are loaded (with or without USS).
TEST_F(LoadAuthFactorMapTest, NoFactors) {
  InstallVaultKeysets({});

  {
    auto no_uss = DisableUssExperiment();
    auto af_map = LoadAuthFactorMap(
        /*is_uss_migration_enabled=*/false, kObfuscatedUsername, platform_,
        converter_, manager_);

    EXPECT_THAT(af_map, IsEmpty());
  }

  {
    auto uss = EnableUssExperiment();
    auto af_map =
        LoadAuthFactorMap(/*is_uss_migration_enabled=*/false,
                          kObfuscatedUsername, platform_, converter_, manager_);

    EXPECT_THAT(af_map, IsEmpty());
  }
}

TEST_F(LoadAuthFactorMapTest, LoadWithOnlyVaultKeysets) {
  auto no_uss = DisableUssExperiment();
  InstallVaultKeysets({{"primary", &CreatePasswordVaultKeyset},
                       {"secondary", &CreatePasswordVaultKeyset}});

  auto af_map = LoadAuthFactorMap(
      /*is_uss_migration_enabled=*/false, kObfuscatedUsername, platform_,
      converter_, manager_);

  EXPECT_THAT(af_map,
              UnorderedElementsAre(
                  AuthFactorMapItem(AuthFactorType::kPassword, "primary",
                                    AuthFactorStorageType::kVaultKeyset),
                  AuthFactorMapItem(AuthFactorType::kPassword, "secondary",
                                    AuthFactorStorageType::kVaultKeyset)));
}

TEST_F(LoadAuthFactorMapTest, LoadWithOnlyUss) {
  auto uss = EnableUssExperiment();
  InstallVaultKeysets({});
  InstallUssFactor(AuthFactor(AuthFactorType::kPassword, "primary",
                              {.metadata = auth_factor::PasswordMetadata()},
                              {.state = TpmBoundToPcrAuthBlockState()}));
  InstallUssFactor(AuthFactor(AuthFactorType::kPin, "secondary",
                              {.metadata = auth_factor::PinMetadata()},
                              {.state = PinWeaverAuthBlockState()}));
  auto af_map = LoadAuthFactorMap(
      /*is_uss_migration_enabled=*/false, kObfuscatedUsername, platform_,
      converter_, manager_);

  EXPECT_THAT(af_map,
              UnorderedElementsAre(
                  AuthFactorMapItem(AuthFactorType::kPassword, "primary",
                                    AuthFactorStorageType::kUserSecretStash),
                  AuthFactorMapItem(AuthFactorType::kPin, "secondary",
                                    AuthFactorStorageType::kUserSecretStash)));
}

// Test that, given a mix of regular VKs, backup VKs, and USS factors, the
// correct ones are loaded depending on whether USS is enabled or disabled.
TEST_F(LoadAuthFactorMapTest, LoadWithMixUsesUssAndVk) {
  InstallVaultKeysets({{"tertiary", &CreatePasswordVaultKeyset},
                       {"quaternary", &CreateBackupVaultKeyset}});
  InstallUssFactor(AuthFactor(AuthFactorType::kPassword, "primary",
                              {.metadata = auth_factor::PasswordMetadata()},
                              {.state = TpmBoundToPcrAuthBlockState()}));
  InstallUssFactor(AuthFactor(AuthFactorType::kPin, "secondary",
                              {.metadata = auth_factor::PinMetadata()},
                              {.state = PinWeaverAuthBlockState()}));

  // Without USS, only the regular and backup VKs should be loaded.
  {
    auto no_uss = DisableUssExperiment();
    auto af_map = LoadAuthFactorMap(
        /*is_uss_migration_enabled=*/false, kObfuscatedUsername, platform_,
        converter_, manager_);

    EXPECT_THAT(af_map,
                UnorderedElementsAre(
                    AuthFactorMapItem(AuthFactorType::kPassword, "tertiary",
                                      AuthFactorStorageType::kVaultKeyset),
                    AuthFactorMapItem(AuthFactorType::kPassword, "quaternary",
                                      AuthFactorStorageType::kVaultKeyset)));
  }

  // With USS, the USS factors should be loaded along with the non-backup VKs.
  {
    auto uss = EnableUssExperiment();
    auto af_map = LoadAuthFactorMap(
        /*is_uss_migration_enabled=*/false, kObfuscatedUsername, platform_,
        converter_, manager_);

    EXPECT_THAT(af_map,
                UnorderedElementsAre(
                    AuthFactorMapItem(AuthFactorType::kPassword, "primary",
                                      AuthFactorStorageType::kUserSecretStash),
                    AuthFactorMapItem(AuthFactorType::kPin, "secondary",
                                      AuthFactorStorageType::kUserSecretStash),
                    AuthFactorMapItem(AuthFactorType::kPassword, "tertiary",
                                      AuthFactorStorageType::kVaultKeyset)));
  }
}

// Test that, given a mix of regular VKs, migrated VKs, and USS factors, the
// correct ones are loaded depending on whether USS migration is enabled or
// disabled.
TEST_F(LoadAuthFactorMapTest, LoadWithMixUsesUssAndMigratedVk) {
  InstallVaultKeysets({{"secondary", &CreatePasswordVaultKeyset},
                       {"primary", &CreateMigratedVaultKeyset}});
  InstallUssFactor(AuthFactor(AuthFactorType::kPassword, "primary",
                              {.metadata = auth_factor::PasswordMetadata()},
                              {.state = TpmBoundToPcrAuthBlockState()}));
  auto no_uss = EnableUssExperiment();

  // Without USS migration, only the regular and migrated VKs should be loaded.
  {
    auto af_map = LoadAuthFactorMap(
        /*is_uss_migration_enabled=*/false, kObfuscatedUsername, platform_,
        converter_, manager_);

    EXPECT_THAT(af_map,
                UnorderedElementsAre(
                    AuthFactorMapItem(AuthFactorType::kPassword, "primary",
                                      AuthFactorStorageType::kVaultKeyset),
                    AuthFactorMapItem(AuthFactorType::kPassword, "secondary",
                                      AuthFactorStorageType::kVaultKeyset)));
  }

  // With USS migration, the USS factors should be loaded along with the regular
  // VKs.
  {
    auto af_map = LoadAuthFactorMap(
        /*is_uss_migration_enabled=*/true, kObfuscatedUsername, platform_,
        converter_, manager_);

    EXPECT_THAT(af_map,
                UnorderedElementsAre(
                    AuthFactorMapItem(AuthFactorType::kPassword, "primary",
                                      AuthFactorStorageType::kUserSecretStash),
                    AuthFactorMapItem(AuthFactorType::kPassword, "secondary",
                                      AuthFactorStorageType::kVaultKeyset)));
  }
}

}  // namespace
}  // namespace cryptohome
