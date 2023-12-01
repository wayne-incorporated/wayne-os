// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secagentd/device_user.h"

#include <memory>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/memory/scoped_refptr.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "base/uuid.h"
#include "dbus/mock_bus.h"
#include "dbus/mock_object_proxy.h"
#include "gmock/gmock.h"  // IWYU pragma: keep
#include "gtest/gtest.h"
#include "session_manager/dbus-proxies.h"
#include "session_manager-client-test/session_manager/dbus-proxy-mocks.h"

namespace secagentd::testing {

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::WithArg;
using ::testing::WithArgs;

constexpr char kDeviceUser[] = "deviceUser@email.com";
constexpr char kSanitized[] = "C02gxaaci";
constexpr char kGuest[] = "GuestUser";
constexpr char kUnknown[] = "Unknown";
constexpr char kAffiliationID[] = "affiliation_id";

class DeviceUserTestFixture : public ::testing::Test {
 protected:
  DeviceUserTestFixture()
      : task_environment_(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}
  void SetUp() override {
    session_manager_ =
        std::make_unique<org::chromium::SessionManagerInterfaceProxyMock>();
    session_manager_ref_ = session_manager_.get();

    ASSERT_TRUE(fake_root_.CreateUniqueTempDir());
    daemon_store_directory_ =
        fake_root_.GetPath().Append("run/daemon-store/secagentd/");
    ASSERT_TRUE(base::CreateDirectory(daemon_store_directory_));

    device_user_ = DeviceUser::CreateForTesting(std::move(session_manager_),
                                                fake_root_.GetPath());
  }

  std::string GetUser() { return device_user_->GetDeviceUser(); }

  void ChangeSessionState(const std::string& state) {
    device_user_->OnSessionStateChange(state);
  }

  std::vector<uint8_t> CreateExpectedDescriptorBlob(const std::string& type,
                                                    const std::string& user) {
    login_manager::PolicyDescriptor descriptor;
    descriptor.set_domain(login_manager::POLICY_DOMAIN_CHROME);
    descriptor.set_account_id(user);

    if (type == "user") {
      descriptor.set_account_type(
          login_manager::PolicyAccountType::ACCOUNT_TYPE_USER);
    } else if (type == "device") {
      descriptor.set_account_type(
          login_manager::PolicyAccountType::ACCOUNT_TYPE_DEVICE);
    } else {
      CHECK(false);
    }

    std::string descriptor_string = descriptor.SerializeAsString();
    return std::vector<uint8_t>(descriptor_string.begin(),
                                descriptor_string.end());
  }

  std::vector<uint8_t> CreatePolicyFetchResponseBlob(
      const std::string& type, const std::string& affiliation_id) {
    // Add ID based on policy type.
    enterprise_management::PolicyData policy_data;
    if (type == "user") {
      auto id = policy_data.add_user_affiliation_ids();
      *id = affiliation_id;
    } else if (type == "device") {
      auto id = policy_data.add_device_affiliation_ids();
      *id = affiliation_id;
    } else {
      CHECK(false);
    }

    enterprise_management::PolicyFetchResponse response;
    CHECK(policy_data.SerializeToString(response.mutable_policy_data()));
    auto serialized = response.SerializeAsString();
    return std::vector<uint8_t>(serialized.begin(), serialized.end());
  }

  void SaveRegisterSessionStateCb() {
    EXPECT_CALL(*session_manager_ref_,
                DoRegisterSessionStateChangedSignalHandler)
        .WillOnce(WithArg<0>(Invoke(
            [this](
                const base::RepeatingCallback<void(const std::string&)>& cb) {
              registration_cb_ = cb;
            })));
  }

  void SetDeviceUser(const std::string& user) {
    device_user_->device_user_ = user;
  }

  base::test::TaskEnvironment task_environment_;
  base::FilePath daemon_store_directory_;
  base::ScopedTempDir fake_root_;
  base::RepeatingCallback<void(const std::string&)> registration_cb_;
  scoped_refptr<DeviceUser> device_user_;
  std::unique_ptr<org::chromium::SessionManagerInterfaceProxyMock>
      session_manager_;
  org::chromium::SessionManagerInterfaceProxyMock* session_manager_ref_;
};

TEST_F(DeviceUserTestFixture, TestAffiliatedUser) {
  EXPECT_CALL(*session_manager_ref_, IsGuestSessionActive)
      .WillOnce(WithArg<0>(Invoke([](bool* is_guest) {
        *is_guest = false;
        return true;
      })));
  EXPECT_CALL(*session_manager_ref_, RetrievePrimarySession)
      .WillOnce(WithArg<0>(Invoke([](std::string* username) {
        *username = kDeviceUser;
        return true;
      })));
  EXPECT_CALL(
      *session_manager_ref_,
      RetrievePolicyEx(CreateExpectedDescriptorBlob("device", ""), _, _, _))
      .WillOnce(WithArg<1>(Invoke([this](std::vector<uint8_t>* out_blob) {
        *out_blob = CreatePolicyFetchResponseBlob("device", kAffiliationID);
        return true;
      })));
  EXPECT_CALL(*session_manager_ref_,
              RetrievePolicyEx(
                  CreateExpectedDescriptorBlob("user", kDeviceUser), _, _, _))
      .WillOnce(WithArg<1>(Invoke([this](std::vector<uint8_t>* out_blob) {
        *out_blob = CreatePolicyFetchResponseBlob("user", kAffiliationID);
        return true;
      })));

  SaveRegisterSessionStateCb();
  device_user_->RegisterSessionChangeHandler();
  registration_cb_.Run("started");
  task_environment_.FastForwardBy(base::Seconds(2));

  EXPECT_EQ(kDeviceUser, device_user_->GetDeviceUser());
}

TEST_F(DeviceUserTestFixture, TestDaemonStoreAffiliated) {
  EXPECT_CALL(*session_manager_ref_, IsGuestSessionActive)
      .WillRepeatedly(WithArg<0>(Invoke([](bool* is_guest) {
        *is_guest = false;
        return true;
      })));
  EXPECT_CALL(*session_manager_ref_, RetrievePrimarySession)
      .WillRepeatedly(WithArgs<0, 1>(
          Invoke([](std::string* username, std::string* sanitized) {
            *username = kDeviceUser;
            *sanitized = kSanitized;
            return true;
          })));
  EXPECT_CALL(
      *session_manager_ref_,
      RetrievePolicyEx(CreateExpectedDescriptorBlob("device", ""), _, _, _))
      .WillOnce(WithArg<1>(Invoke([this](std::vector<uint8_t>* out_blob) {
        *out_blob = CreatePolicyFetchResponseBlob("device", kAffiliationID);
        return true;
      })));
  EXPECT_CALL(*session_manager_ref_,
              RetrievePolicyEx(
                  CreateExpectedDescriptorBlob("user", kDeviceUser), _, _, _))
      .Times(1)
      .WillOnce(WithArg<1>(Invoke([this](std::vector<uint8_t>* out_blob) {
        *out_blob = CreatePolicyFetchResponseBlob("user", kAffiliationID);
        return true;
      })));
  ASSERT_TRUE(
      base::CreateDirectory(daemon_store_directory_.Append(kSanitized)));

  SaveRegisterSessionStateCb();
  device_user_->RegisterSessionChangeHandler();
  registration_cb_.Run("started");
  task_environment_.FastForwardBy(base::Seconds(2));

  EXPECT_EQ(kDeviceUser, device_user_->GetDeviceUser());
  base::FilePath username_file =
      daemon_store_directory_.Append(kSanitized).Append("username");
  ASSERT_TRUE(base::PathExists(username_file));
  std::string username;
  ASSERT_TRUE(base::ReadFileToString(username_file, &username));
  EXPECT_EQ(kDeviceUser, username);

  // Trigger callback again to verify the file is read from.
  SetDeviceUser("");
  registration_cb_.Run("started");
  task_environment_.FastForwardBy(base::Seconds(2));
  EXPECT_EQ(kDeviceUser, device_user_->GetDeviceUser());
}

TEST_F(DeviceUserTestFixture, TestDaemonStoreUnaffiliated) {
  EXPECT_CALL(*session_manager_ref_, IsGuestSessionActive)
      .WillRepeatedly(WithArg<0>(Invoke([](bool* is_guest) {
        *is_guest = false;
        return true;
      })));
  EXPECT_CALL(*session_manager_ref_, RetrievePrimarySession)
      .WillRepeatedly(WithArgs<0, 1>(
          Invoke([](std::string* username, std::string* sanitized) {
            *username = kDeviceUser;
            *sanitized = kSanitized;
            return true;
          })));
  EXPECT_CALL(
      *session_manager_ref_,
      RetrievePolicyEx(CreateExpectedDescriptorBlob("device", ""), _, _, _))
      .WillOnce(WithArg<1>(Invoke([this](std::vector<uint8_t>* out_blob) {
        *out_blob = CreatePolicyFetchResponseBlob("device", kAffiliationID);
        return true;
      })));
  EXPECT_CALL(*session_manager_ref_,
              RetrievePolicyEx(
                  CreateExpectedDescriptorBlob("user", kDeviceUser), _, _, _))
      .Times(1)
      .WillOnce(WithArg<1>(Invoke([this](std::vector<uint8_t>* out_blob) {
        *out_blob = CreatePolicyFetchResponseBlob("user", "DifferentID");
        return true;
      })));
  ASSERT_TRUE(
      base::CreateDirectory(daemon_store_directory_.Append(kSanitized)));

  SaveRegisterSessionStateCb();
  device_user_->RegisterSessionChangeHandler();
  registration_cb_.Run("started");
  task_environment_.FastForwardBy(base::Seconds(2));

  // Just verify that the username is a valid uuid because it
  // is random each time.
  EXPECT_TRUE(base::Uuid::ParseCaseInsensitive(device_user_->GetDeviceUser())
                  .is_valid());
  base::FilePath username_file =
      daemon_store_directory_.Append(kSanitized).Append("username");
  ASSERT_TRUE(base::PathExists(username_file));
  std::string username;
  ASSERT_TRUE(base::ReadFileToString(username_file, &username));
  EXPECT_TRUE(base::Uuid::ParseCaseInsensitive(username).is_valid());

  // Trigger callback again to verify the file is read from.
  SetDeviceUser("");
  registration_cb_.Run("started");
  task_environment_.FastForwardBy(base::Seconds(2));
  EXPECT_TRUE(base::Uuid::ParseCaseInsensitive(device_user_->GetDeviceUser())
                  .is_valid());
}

TEST_F(DeviceUserTestFixture, TestLogout) {
  SetDeviceUser(kDeviceUser);
  SaveRegisterSessionStateCb();
  device_user_->RegisterSessionChangeHandler();
  registration_cb_.Run("stopped");
  EXPECT_EQ("", device_user_->GetDeviceUser());

  SetDeviceUser(kDeviceUser);
  SaveRegisterSessionStateCb();
  device_user_->RegisterSessionChangeHandler();
  registration_cb_.Run("stopping");
  EXPECT_EQ("", device_user_->GetDeviceUser());
}

TEST_F(DeviceUserTestFixture, TestUnaffiliatedUser) {
  EXPECT_CALL(*session_manager_ref_, IsGuestSessionActive)
      .WillOnce(WithArg<0>(Invoke([](bool* is_guest) {
        *is_guest = false;
        return true;
      })));
  EXPECT_CALL(*session_manager_ref_, RetrievePrimarySession)
      .WillOnce(WithArg<0>(Invoke([](std::string* username) {
        *username = kDeviceUser;
        return true;
      })));
  EXPECT_CALL(
      *session_manager_ref_,
      RetrievePolicyEx(CreateExpectedDescriptorBlob("device", ""), _, _, _))
      .WillOnce(WithArg<1>(Invoke([this](std::vector<uint8_t>* out_blob) {
        *out_blob = CreatePolicyFetchResponseBlob("device", kAffiliationID);
        return true;
      })));
  EXPECT_CALL(*session_manager_ref_,
              RetrievePolicyEx(
                  CreateExpectedDescriptorBlob("user", kDeviceUser), _, _, _))
      .WillOnce(WithArg<1>(Invoke([this](std::vector<uint8_t>* out_blob) {
        *out_blob = CreatePolicyFetchResponseBlob("user", "DifferentID");
        return true;
      })));

  SaveRegisterSessionStateCb();
  device_user_->RegisterSessionChangeHandler();
  registration_cb_.Run("started");
  task_environment_.FastForwardBy(base::Seconds(2));

  EXPECT_TRUE(base::IsValidUuid(device_user_->GetDeviceUser()));
}

TEST_F(DeviceUserTestFixture, TestGuestUser) {
  EXPECT_CALL(*session_manager_ref_, RetrievePolicyEx)
      .WillOnce(WithArg<1>(Invoke([this](std::vector<uint8_t>* out_blob) {
        *out_blob = CreatePolicyFetchResponseBlob("device", kAffiliationID);
        return true;
      })));
  EXPECT_CALL(*session_manager_ref_, IsGuestSessionActive)
      .WillOnce(WithArg<0>(Invoke([](bool* is_guest) {
        *is_guest = true;
        return true;
      })));

  SaveRegisterSessionStateCb();
  device_user_->RegisterSessionChangeHandler();
  registration_cb_.Run("started");
  task_environment_.FastForwardBy(base::Seconds(2));

  EXPECT_EQ(kGuest, device_user_->GetDeviceUser());
}

TEST_F(DeviceUserTestFixture, TestFailedRegistration) {
  EXPECT_CALL(*session_manager_ref_, DoRegisterSessionStateChangedSignalHandler)
      .WillOnce(WithArg<1>(
          Invoke([](base::OnceCallback<void(const std::string&,
                                            const std::string&, bool)>* cb) {
            std::move(*cb).Run("dbus", "register", false);
          })));

  device_user_->RegisterSessionChangeHandler();

  EXPECT_EQ(kUnknown, device_user_->GetDeviceUser());
}

TEST_F(DeviceUserTestFixture, TestFailedGuestSessionRetrieval) {
  EXPECT_CALL(*session_manager_ref_, RetrievePolicyEx)
      .WillOnce(WithArg<1>(Invoke([this](std::vector<uint8_t>* out_blob) {
        *out_blob = CreatePolicyFetchResponseBlob("device", kAffiliationID);
        return true;
      })));
  EXPECT_CALL(*session_manager_ref_, IsGuestSessionActive)
      .WillOnce(WithArg<1>(Invoke([](brillo::ErrorPtr* error) {
        *error = brillo::Error::Create(FROM_HERE, "", "",
                                       "IsGuestSessionActive failed");
        return false;
      })));
  EXPECT_CALL(*session_manager_ref_, RetrievePrimarySession)
      .WillOnce(WithArg<0>(Invoke([](std::string* username) {
        *username = "";
        return true;
      })));

  SaveRegisterSessionStateCb();
  device_user_->RegisterSessionChangeHandler();
  registration_cb_.Run("started");
  task_environment_.FastForwardBy(base::Seconds(2));

  EXPECT_EQ(kUnknown, device_user_->GetDeviceUser());
}

TEST_F(DeviceUserTestFixture, TestFailedPrimarySessionRetrieval) {
  EXPECT_CALL(*session_manager_ref_, RetrievePolicyEx)
      .WillOnce(WithArg<1>(Invoke([this](std::vector<uint8_t>* out_blob) {
        *out_blob = CreatePolicyFetchResponseBlob("device", kAffiliationID);
        return true;
      })));
  EXPECT_CALL(*session_manager_ref_, IsGuestSessionActive)
      .WillOnce(WithArg<0>(Invoke([](bool* is_guest) {
        *is_guest = false;
        return true;
      })));
  EXPECT_CALL(*session_manager_ref_, RetrievePrimarySession)
      .WillOnce(WithArg<2>(Invoke([](brillo::ErrorPtr* error) {
        *error =
            brillo::Error::Create(FROM_HERE, "", "", "RetrievePolicyEx failed");
        return false;
      })));

  SaveRegisterSessionStateCb();
  device_user_->RegisterSessionChangeHandler();
  registration_cb_.Run("started");
  task_environment_.FastForwardBy(base::Seconds(2));

  EXPECT_EQ(kUnknown, device_user_->GetDeviceUser());
}

TEST_F(DeviceUserTestFixture, TestFailedRetrievePolicyEx) {
  EXPECT_CALL(*session_manager_ref_, RetrievePolicyEx)
      .Times(2)
      .WillRepeatedly(WithArg<2>(Invoke([](brillo::ErrorPtr* error) {
        *error =
            brillo::Error::Create(FROM_HERE, "", "", "RetrievePolicyEx failed");
        return false;
      })));
  EXPECT_CALL(*session_manager_ref_, IsGuestSessionActive)
      .WillOnce(WithArg<0>(Invoke([](bool* is_guest) {
        *is_guest = false;
        return true;
      })));
  EXPECT_CALL(*session_manager_ref_, RetrievePrimarySession)
      .WillOnce(WithArg<0>(Invoke([](std::string* username) {
        *username = kDeviceUser;
        return true;
      })));

  SaveRegisterSessionStateCb();
  device_user_->RegisterSessionChangeHandler();
  registration_cb_.Run("started");
  task_environment_.FastForwardBy(base::Seconds(2));

  EXPECT_EQ(kUnknown, device_user_->GetDeviceUser());
}

TEST_F(DeviceUserTestFixture, TestFailedParsingResponse) {
  EXPECT_CALL(*session_manager_ref_, IsGuestSessionActive)
      .WillOnce(WithArg<0>(Invoke([](bool* is_guest) {
        *is_guest = false;
        return true;
      })));
  EXPECT_CALL(*session_manager_ref_, RetrievePrimarySession)
      .WillOnce(WithArg<0>(Invoke([](std::string* username) {
        *username = kDeviceUser;
        return true;
      })));
  EXPECT_CALL(
      *session_manager_ref_,
      RetrievePolicyEx(CreateExpectedDescriptorBlob("device", ""), _, _, _))
      .WillOnce(WithArg<1>(Invoke([this](std::vector<uint8_t>* out_blob) {
        *out_blob = CreatePolicyFetchResponseBlob("device", kAffiliationID);
        return true;
      })));
  EXPECT_CALL(*session_manager_ref_,
              RetrievePolicyEx(
                  CreateExpectedDescriptorBlob("user", kDeviceUser), _, _, _))
      .WillOnce(WithArg<1>(Invoke([](std::vector<uint8_t>* out_blob) {
        std::vector<uint8_t> bad_blob;
        bad_blob.push_back(1);
        *out_blob = bad_blob;
        return true;
      })));

  SaveRegisterSessionStateCb();
  device_user_->RegisterSessionChangeHandler();
  registration_cb_.Run("started");
  task_environment_.FastForwardBy(base::Seconds(2));

  EXPECT_EQ(kUnknown, device_user_->GetDeviceUser());
}

TEST_F(DeviceUserTestFixture, TestFailedParsingPolicy) {
  EXPECT_CALL(*session_manager_ref_, IsGuestSessionActive)
      .WillOnce(WithArg<0>(Invoke([](bool* is_guest) {
        *is_guest = false;
        return true;
      })));
  EXPECT_CALL(*session_manager_ref_, RetrievePrimarySession)
      .WillOnce(WithArg<0>(Invoke([](std::string* username) {
        *username = kDeviceUser;
        return true;
      })));
  EXPECT_CALL(
      *session_manager_ref_,
      RetrievePolicyEx(CreateExpectedDescriptorBlob("device", ""), _, _, _))
      .WillOnce(WithArg<1>(Invoke([this](std::vector<uint8_t>* out_blob) {
        *out_blob = CreatePolicyFetchResponseBlob("device", kAffiliationID);
        return true;
      })));
  EXPECT_CALL(*session_manager_ref_,
              RetrievePolicyEx(
                  CreateExpectedDescriptorBlob("user", kDeviceUser), _, _, _))
      .WillOnce(WithArg<1>(Invoke([](std::vector<uint8_t>* out_blob) {
        std::vector<uint8_t> bad_blob;
        bad_blob.push_back(1);
        *out_blob = bad_blob;
        return true;
      })));

  SaveRegisterSessionStateCb();
  device_user_->RegisterSessionChangeHandler();
  registration_cb_.Run("started");
  task_environment_.FastForwardBy(base::Seconds(2));

  EXPECT_EQ(kUnknown, device_user_->GetDeviceUser());
}

}  // namespace secagentd::testing
