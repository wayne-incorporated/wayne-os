// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/device_local_account_manager.h"

#include <algorithm>
#include <memory>
#include <utility>

#include <base/compiler_specific.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/memory/ptr_util.h>
#include <base/run_loop.h>
#include <brillo/cryptohome.h>
#include <brillo/message_loops/fake_message_loop.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "bindings/chrome_device_policy.pb.h"
#include "login_manager/blob_util.h"
#include "login_manager/mock_policy_key.h"
#include "login_manager/mock_policy_service.h"
#include "login_manager/mock_policy_store.h"

namespace em = enterprise_management;

using testing::_;
using testing::Return;

namespace login_manager {
namespace {

// Returns blob containing serialized policy proto for testing.
std::vector<uint8_t> GetTestPolicyBlob() {
  em::PolicyFetchResponse policy_proto;
  policy_proto.set_policy_data("policy-data");
  policy_proto.set_policy_data_signature("policy-data-signature");
  return SerializeAsBlob(policy_proto);
}

}  // namespace

class DeviceLocalAccountManagerTest : public ::testing::Test {
 public:
  DeviceLocalAccountManagerTest() = default;
  DeviceLocalAccountManagerTest(const DeviceLocalAccountManagerTest&) = delete;
  DeviceLocalAccountManagerTest& operator=(
      const DeviceLocalAccountManagerTest&) = delete;

  void SetUp() override {
    fake_loop_.SetAsCurrent();
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    brillo::cryptohome::home::SetSystemSalt(&salt_);

    fake_account_policy_path_ =
        temp_dir_.GetPath()
            .Append(brillo::cryptohome::home::SanitizeUserName(fake_account_))
            .Append(DeviceLocalAccountManager::kPolicyDir)
            .Append(PolicyService::kChromePolicyFileName);

    manager_ =
        std::make_unique<DeviceLocalAccountManager>(temp_dir_.GetPath(), &key_);
  }

  void SetupAccount() {
    em::ChromeDeviceSettingsProto device_settings;
    em::DeviceLocalAccountInfoProto* account =
        device_settings.mutable_device_local_accounts()->add_account();
    account->set_type(
        em::DeviceLocalAccountInfoProto::ACCOUNT_TYPE_PUBLIC_SESSION);
    account->set_account_id(fake_account_);
    manager_->UpdateDeviceSettings(device_settings);
  }

  void SetupKey() {
    EXPECT_CALL(key_, PopulateFromDiskIfPossible()).Times(0);
    EXPECT_CALL(key_, IsPopulated()).WillRepeatedly(Return(true));
    EXPECT_CALL(key_, Verify(_, _)).WillRepeatedly(Return(true));
  }

 protected:
  std::string salt_ = "salt";

  const std::string fake_account_ = "account@example.com";
  base::FilePath fake_account_policy_path_;

  brillo::FakeMessageLoop fake_loop_{nullptr};
  base::ScopedTempDir temp_dir_;

  MockPolicyKey key_;

  std::unique_ptr<DeviceLocalAccountManager> manager_;
};

TEST_F(DeviceLocalAccountManagerTest, GetPolicyServiceFailsNoAccount) {
  EXPECT_EQ(nullptr, manager_->GetPolicyService(fake_account_));
  fake_loop_.Run();
  EXPECT_FALSE(base::PathExists(fake_account_policy_path_));
}

TEST_F(DeviceLocalAccountManagerTest, GetPolicyServiceSucceeds) {
  SetupAccount();
  SetupKey();

  PolicyService* service = manager_->GetPolicyService(fake_account_);
  ASSERT_TRUE(service);

  // Also check  if policy is stored at the proper path.
  ASSERT_TRUE(service->Store(MakeChromePolicyNamespace(), GetTestPolicyBlob(),
                             PolicyService::KEY_NONE, SignatureCheck::kEnabled,
                             MockPolicyService::CreateExpectSuccessCallback()));
  fake_loop_.Run();
  EXPECT_TRUE(base::PathExists(fake_account_policy_path_));
}

// PolicyServices are created on demand. PersistAllPolicy() should not try to
// to access uninitialized PolicyServices, see crbug.com/818302.
TEST_F(DeviceLocalAccountManagerTest, PersistUninitializedAccounts) {
  SetupAccount();
  manager_->PersistAllPolicy();
}

TEST_F(DeviceLocalAccountManagerTest, PurgeStaleAccounts) {
  SetupKey();

  ASSERT_TRUE(base::CreateDirectory(fake_account_policy_path_.DirName()));
  ASSERT_TRUE(WriteBlobToFile(fake_account_policy_path_, GetTestPolicyBlob()));

  em::ChromeDeviceSettingsProto device_settings;
  manager_->UpdateDeviceSettings(device_settings);
  EXPECT_FALSE(base::PathExists(fake_account_policy_path_));
}

TEST_F(DeviceLocalAccountManagerTest, MigrateUppercaseDirs) {
  const char* kDir1 = "356a192b7913b04c54574d18c28d46e6395428ab";
  const char* kDir2 = "DA4B9237BACCCDF19C0760CAB7AEC4A8359010B0";
  const char* kDir2Lower = "da4b9237bacccdf19c0760cab7aec4a8359010b0";
  const char* kUnrelated = "foobar";

  base::FilePath fp1(temp_dir_.GetPath().Append(kDir1));
  base::FilePath fp2(temp_dir_.GetPath().Append(kDir2));
  base::FilePath fp2lower(temp_dir_.GetPath().Append(kDir2Lower));
  base::FilePath fpunrel(temp_dir_.GetPath().Append(kUnrelated));

  EXPECT_TRUE(base::CreateDirectory(fp1));
  EXPECT_TRUE(base::CreateDirectory(fp2));
  EXPECT_TRUE(base::CreateDirectory(fpunrel));

  EXPECT_TRUE(manager_->MigrateUppercaseDirs());

  EXPECT_TRUE(base::DirectoryExists(fp1));
  EXPECT_FALSE(base::DirectoryExists(fp2));
  EXPECT_TRUE(base::DirectoryExists(fp2lower));
  EXPECT_TRUE(base::DirectoryExists(fpunrel));
}

TEST_F(DeviceLocalAccountManagerTest, LegacyPublicSessionIdFallback) {
  // Check that a legacy public session ID continues to work as long as the
  // account_id / type fields are not present.
  em::ChromeDeviceSettingsProto device_settings;
  em::DeviceLocalAccountInfoProto* account =
      device_settings.mutable_device_local_accounts()->add_account();
  account->set_deprecated_public_session_id(fake_account_);
  manager_->UpdateDeviceSettings(device_settings);
  SetupKey();

  ASSERT_TRUE(manager_->GetPolicyService(fake_account_));
}

TEST_F(DeviceLocalAccountManagerTest, LegacyPublicSessionIdIgnored) {
  // If there's a legacy public session ID and an account id / type pair, the
  // former should get ignored.
  const char kDeprecatedId[] = "deprecated";
  em::ChromeDeviceSettingsProto device_settings;
  em::DeviceLocalAccountInfoProto* account =
      device_settings.mutable_device_local_accounts()->add_account();
  account->set_deprecated_public_session_id(kDeprecatedId);
  account->set_type(
      em::DeviceLocalAccountInfoProto::ACCOUNT_TYPE_PUBLIC_SESSION);
  account->set_account_id(fake_account_);
  manager_->UpdateDeviceSettings(device_settings);
  SetupKey();

  EXPECT_FALSE(manager_->GetPolicyService(kDeprecatedId));
}

}  // namespace login_manager
