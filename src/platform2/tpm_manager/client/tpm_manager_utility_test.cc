// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/client/tpm_manager_utility.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>

#include <tpm_manager-client-test/tpm_manager/dbus-proxy-mocks.h>

namespace {

using ::testing::_;
using ::testing::ByRef;
using ::testing::ElementsAreArray;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::Test;
using ::testing::WithArg;

// testing::InvokeArgument<N> does not work with base::OnceCallback, need to use
// |ACTION_TAMPLATE| along with predefined |args| tuple.
ACTION_TEMPLATE(InvokeCallbackArgument,
                HAS_1_TEMPLATE_PARAMS(int, k),
                AND_1_VALUE_PARAMS(p0)) {
  // Runs it as base::OnceCallback anyway.
  std::move(const_cast<typename std::remove_cv<typename std::remove_reference<
                decltype(std::get<k>(args))>::type>::type&>(std::get<k>(args)))
      .Run(p0);
}

}  // namespace

namespace tpm_manager {

class TpmManagerUtilityTest : public Test {
 protected:
  // Uses contructor and SetUp at the same time so we can take advantage of
  // both sytles of initialization.
  TpmManagerUtilityTest()
      : tpm_manager_utility_(&mock_tpm_owner_, &mock_tpm_nvram_) {
    // for the following ON_CALL setup, pass the fake replies by reference so we
    // can change the contained data dynamically in a test item.
    ON_CALL(mock_tpm_owner_, TakeOwnershipAsync(_, _, _, _))
        .WillByDefault(InvokeCallbackArgument<1>(ByRef(take_ownership_reply_)));
    ON_CALL(mock_tpm_owner_, GetTpmStatusAsync(_, _, _, _))
        .WillByDefault(InvokeCallbackArgument<1>(ByRef(get_tpm_status_reply_)));
    ON_CALL(mock_tpm_owner_, GetTpmNonsensitiveStatusAsync(_, _, _, _))
        .WillByDefault(InvokeCallbackArgument<1>(
            ByRef(get_tpm_nonsensitive_status_reply_)));
    ON_CALL(mock_tpm_owner_, GetVersionInfoAsync(_, _, _, _))
        .WillByDefault(
            InvokeCallbackArgument<1>(ByRef(get_version_info_reply_)));
    ON_CALL(mock_tpm_owner_, RemoveOwnerDependencyAsync(_, _, _, _))
        .WillByDefault(
            InvokeCallbackArgument<1>(ByRef(remove_owner_dependency_reply_)));
    ON_CALL(mock_tpm_owner_, ClearStoredOwnerPasswordAsync(_, _, _, _))
        .WillByDefault(InvokeCallbackArgument<1>(
            ByRef(clear_stored_owner_password_reply_)));
    ON_CALL(mock_tpm_owner_, GetDictionaryAttackInfoAsync(_, _, _, _))
        .WillByDefault(InvokeCallbackArgument<1>(
            ByRef(get_dictionary_attack_info_reply_)));
    ON_CALL(mock_tpm_owner_, ResetDictionaryAttackLockAsync(_, _, _, _))
        .WillByDefault(InvokeCallbackArgument<1>(
            ByRef(reset_dictionary_attack_lock_reply_)));
    ON_CALL(mock_tpm_nvram_, DestroySpaceAsync(_, _, _, _))
        .WillByDefault(InvokeCallbackArgument<1>(ByRef(destroy_space_reply_)));
    ON_CALL(mock_tpm_nvram_, ListSpacesAsync(_, _, _, _))
        .WillByDefault(InvokeCallbackArgument<1>(ByRef(list_spaces_reply_)));
    ON_CALL(mock_tpm_nvram_, GetSpaceInfoAsync(_, _, _, _))
        .WillByDefault(InvokeCallbackArgument<1>(ByRef(get_space_info_reply_)));
    ON_CALL(mock_tpm_nvram_, LockSpaceAsync(_, _, _, _))
        .WillByDefault(InvokeCallbackArgument<1>(ByRef(lock_space_reply_)));
  }
  void SetUp() override { ASSERT_TRUE(tpm_manager_utility_.Initialize()); }

  void RunReadSpaceTest(bool use_owner_auth,
                        tpm_manager::NvramResult result,
                        std::optional<std::string> value,
                        bool expect_success);

  void RunDefineSpaceTest(bool write_define,
                          bool bind_to_pcr0,
                          bool firmware_readable,
                          tpm_manager::NvramResult result,
                          bool expect_success);

  void RunWriteSpaceTest(bool use_owner_auth,
                         tpm_manager::NvramResult result,
                         bool expect_success);

  NiceMock<org::chromium::TpmManagerProxyMock> mock_tpm_owner_;
  NiceMock<org::chromium::TpmNvramProxyMock> mock_tpm_nvram_;
  TpmManagerUtility tpm_manager_utility_;

  // fake replies from TpmManager
  tpm_manager::TakeOwnershipReply take_ownership_reply_;
  tpm_manager::GetTpmStatusReply get_tpm_status_reply_;
  tpm_manager::GetTpmNonsensitiveStatusReply get_tpm_nonsensitive_status_reply_;
  tpm_manager::GetVersionInfoReply get_version_info_reply_;
  tpm_manager::RemoveOwnerDependencyReply remove_owner_dependency_reply_;
  tpm_manager::ClearStoredOwnerPasswordReply clear_stored_owner_password_reply_;
  tpm_manager::GetDictionaryAttackInfoReply get_dictionary_attack_info_reply_;
  tpm_manager::ResetDictionaryAttackLockReply
      reset_dictionary_attack_lock_reply_;
  tpm_manager::DestroySpaceReply destroy_space_reply_;
  tpm_manager::ListSpacesReply list_spaces_reply_;
  tpm_manager::GetSpaceInfoReply get_space_info_reply_;
  tpm_manager::LockSpaceReply lock_space_reply_;
};

TEST_F(TpmManagerUtilityTest, TakeOwnership) {
  take_ownership_reply_.set_status(tpm_manager::STATUS_SUCCESS);
  EXPECT_TRUE(tpm_manager_utility_.TakeOwnership());
}

TEST_F(TpmManagerUtilityTest, TakeOwnershipFail) {
  take_ownership_reply_.set_status(tpm_manager::STATUS_DEVICE_ERROR);
  EXPECT_FALSE(tpm_manager_utility_.TakeOwnership());
  take_ownership_reply_.set_status(tpm_manager::STATUS_NOT_AVAILABLE);
  EXPECT_FALSE(tpm_manager_utility_.TakeOwnership());
}

TEST_F(TpmManagerUtilityTest, GetTpmStatus) {
  bool is_enabled = true;
  bool is_owned = true;
  tpm_manager::LocalData local_data;
  get_tpm_status_reply_.set_status(tpm_manager::STATUS_SUCCESS);

  get_tpm_status_reply_.set_enabled(false);
  get_tpm_status_reply_.set_owned(false);
  EXPECT_TRUE(
      tpm_manager_utility_.GetTpmStatus(&is_enabled, &is_owned, &local_data));
  EXPECT_EQ(is_enabled, get_tpm_status_reply_.enabled());
  EXPECT_EQ(is_owned, get_tpm_status_reply_.owned());

  get_tpm_status_reply_.set_enabled(true);
  get_tpm_status_reply_.set_owned(true);
  tpm_manager::LocalData expected_local_data;
  expected_local_data.set_owner_password("owner_password");
  expected_local_data.set_endorsement_password("endorsement_password");
  expected_local_data.set_lockout_password("lockout_password");
  expected_local_data.mutable_owner_delegate()->set_blob("blob");
  expected_local_data.mutable_owner_delegate()->set_secret("secret");
  get_tpm_status_reply_.mutable_local_data()->CopyFrom(expected_local_data);
  EXPECT_TRUE(
      tpm_manager_utility_.GetTpmStatus(&is_enabled, &is_owned, &local_data));
  EXPECT_EQ(is_enabled, get_tpm_status_reply_.enabled());
  EXPECT_EQ(is_owned, get_tpm_status_reply_.owned());
  EXPECT_EQ(expected_local_data.SerializeAsString(),
            local_data.SerializeAsString());
}

TEST_F(TpmManagerUtilityTest, GetTpmStatusFail) {
  bool is_enabled{false};
  bool is_owned{false};
  tpm_manager::LocalData local_data;

  get_tpm_status_reply_.set_status(tpm_manager::STATUS_DEVICE_ERROR);
  EXPECT_FALSE(
      tpm_manager_utility_.GetTpmStatus(&is_enabled, &is_owned, &local_data));

  get_tpm_status_reply_.set_status(tpm_manager::STATUS_NOT_AVAILABLE);
  EXPECT_FALSE(
      tpm_manager_utility_.GetTpmStatus(&is_enabled, &is_owned, &local_data));
}

TEST_F(TpmManagerUtilityTest, GetTpmNonsensitiveStatus) {
  bool is_enabled = false;
  bool is_owned = false;
  bool is_owner_password_present = true;
  bool has_reset_lock_permissions = false;
  get_tpm_nonsensitive_status_reply_.set_status(tpm_manager::STATUS_SUCCESS);

  get_tpm_nonsensitive_status_reply_.set_is_owner_password_present(false);
  // We allow to set nullptr for unused field.
  EXPECT_TRUE(tpm_manager_utility_.GetTpmNonsensitiveStatus(
      nullptr, nullptr, &is_owner_password_present, nullptr));
  EXPECT_EQ(is_owner_password_present,
            get_tpm_nonsensitive_status_reply_.is_owner_password_present());

  get_tpm_nonsensitive_status_reply_.set_is_enabled(true);
  get_tpm_nonsensitive_status_reply_.set_is_owned(false);
  get_tpm_nonsensitive_status_reply_.set_is_owner_password_present(true);
  get_tpm_nonsensitive_status_reply_.set_has_reset_lock_permissions(false);
  EXPECT_TRUE(tpm_manager_utility_.GetTpmNonsensitiveStatus(
      &is_enabled, &is_owned, &is_owner_password_present,
      &has_reset_lock_permissions));
  EXPECT_EQ(is_enabled, get_tpm_nonsensitive_status_reply_.is_enabled());
  EXPECT_EQ(is_owned, get_tpm_nonsensitive_status_reply_.is_owned());
  EXPECT_EQ(is_owner_password_present,
            get_tpm_nonsensitive_status_reply_.is_owner_password_present());
  EXPECT_EQ(has_reset_lock_permissions,
            get_tpm_nonsensitive_status_reply_.has_reset_lock_permissions());

  get_tpm_nonsensitive_status_reply_.set_is_enabled(false);
  get_tpm_nonsensitive_status_reply_.set_is_owned(true);
  get_tpm_nonsensitive_status_reply_.set_is_owner_password_present(false);
  get_tpm_nonsensitive_status_reply_.set_has_reset_lock_permissions(true);
  EXPECT_TRUE(tpm_manager_utility_.GetTpmNonsensitiveStatus(
      &is_enabled, &is_owned, &is_owner_password_present,
      &has_reset_lock_permissions));
  EXPECT_EQ(is_enabled, get_tpm_nonsensitive_status_reply_.is_enabled());
  EXPECT_EQ(is_owned, get_tpm_nonsensitive_status_reply_.is_owned());
  EXPECT_EQ(is_owner_password_present,
            get_tpm_nonsensitive_status_reply_.is_owner_password_present());
  EXPECT_EQ(has_reset_lock_permissions,
            get_tpm_nonsensitive_status_reply_.has_reset_lock_permissions());

  get_tpm_nonsensitive_status_reply_.set_is_enabled(true);
  get_tpm_nonsensitive_status_reply_.set_is_owned(false);
  get_tpm_nonsensitive_status_reply_.set_has_reset_lock_permissions(false);
  EXPECT_TRUE(tpm_manager_utility_.GetTpmNonsensitiveStatus(
      &is_enabled, &is_owned, nullptr, &has_reset_lock_permissions));
  EXPECT_EQ(is_enabled, get_tpm_nonsensitive_status_reply_.is_enabled());
  EXPECT_EQ(is_owned, get_tpm_nonsensitive_status_reply_.is_owned());
  EXPECT_EQ(has_reset_lock_permissions,
            get_tpm_nonsensitive_status_reply_.has_reset_lock_permissions());
}

TEST_F(TpmManagerUtilityTest, GetTpmNonsensitiveStatusFail) {
  bool is_enabled = false;
  bool is_owned = false;
  bool is_owner_password_present = false;
  bool has_reset_lock_permissions = false;

  get_tpm_nonsensitive_status_reply_.set_status(
      tpm_manager::STATUS_DEVICE_ERROR);
  EXPECT_FALSE(tpm_manager_utility_.GetTpmNonsensitiveStatus(
      &is_enabled, &is_owned, &is_owner_password_present,
      &has_reset_lock_permissions));

  get_tpm_nonsensitive_status_reply_.set_status(
      tpm_manager::STATUS_NOT_AVAILABLE);
  EXPECT_FALSE(tpm_manager_utility_.GetTpmNonsensitiveStatus(
      &is_enabled, &is_owned, &is_owner_password_present,
      &has_reset_lock_permissions));
}

TEST_F(TpmManagerUtilityTest, GetVersionInfo) {
  uint32_t family = 0;
  uint64_t spec_level = 0;
  uint32_t manufacturer = 0;
  uint32_t tpm_model = 0;
  uint64_t firmware_version = 0;
  std::string vendor_specific;

  get_version_info_reply_.set_status(tpm_manager::STATUS_SUCCESS);
  get_version_info_reply_.set_family(1);
  get_version_info_reply_.set_spec_level(2);
  get_version_info_reply_.set_manufacturer(3);
  get_version_info_reply_.set_tpm_model(4);
  get_version_info_reply_.set_firmware_version(5);
  get_version_info_reply_.set_vendor_specific("aa");

  EXPECT_TRUE(tpm_manager_utility_.GetVersionInfo(
      &family, &spec_level, &manufacturer, &tpm_model, &firmware_version,
      &vendor_specific));
  EXPECT_EQ(family, 1);
  EXPECT_EQ(spec_level, 2);
  EXPECT_EQ(manufacturer, 3);
  EXPECT_EQ(tpm_model, 4);
  EXPECT_EQ(firmware_version, 5);
  EXPECT_EQ(vendor_specific, "aa");
}

TEST_F(TpmManagerUtilityTest, GetVersionInfoFail) {
  EXPECT_FALSE(tpm_manager_utility_.GetVersionInfo(nullptr, nullptr, nullptr,
                                                   nullptr, nullptr, nullptr));

  uint32_t family;
  uint64_t spec_level;
  uint32_t manufacturer;
  uint32_t tpm_model;
  uint64_t firmware_version;
  std::string vendor_specific;

  get_version_info_reply_.set_status(tpm_manager::STATUS_DEVICE_ERROR);
  EXPECT_FALSE(tpm_manager_utility_.GetVersionInfo(
      &family, &spec_level, &manufacturer, &tpm_model, &firmware_version,
      &vendor_specific));

  get_version_info_reply_.set_status(tpm_manager::STATUS_NOT_AVAILABLE);
  EXPECT_FALSE(tpm_manager_utility_.GetVersionInfo(
      &family, &spec_level, &manufacturer, &tpm_model, &firmware_version,
      &vendor_specific));
}

TEST_F(TpmManagerUtilityTest, RemoveOwnerDependency) {
  remove_owner_dependency_reply_.set_status(tpm_manager::STATUS_SUCCESS);
  EXPECT_TRUE(tpm_manager_utility_.RemoveOwnerDependency(""));
}

TEST_F(TpmManagerUtilityTest, RemoveOwnerDependencyFail) {
  remove_owner_dependency_reply_.set_status(tpm_manager::STATUS_DEVICE_ERROR);
  EXPECT_FALSE(tpm_manager_utility_.RemoveOwnerDependency(""));

  remove_owner_dependency_reply_.set_status(tpm_manager::STATUS_NOT_AVAILABLE);
  EXPECT_FALSE(tpm_manager_utility_.RemoveOwnerDependency(""));
}

TEST_F(TpmManagerUtilityTest, GetDictionaryAttackInfo) {
  int counter = 0;
  int threshold = 0;
  bool lockout = false;
  int seconds_remaining = 0;
  get_dictionary_attack_info_reply_.set_status(tpm_manager::STATUS_SUCCESS);
  get_dictionary_attack_info_reply_.set_dictionary_attack_counter(123);
  get_dictionary_attack_info_reply_.set_dictionary_attack_threshold(456);
  get_dictionary_attack_info_reply_.set_dictionary_attack_lockout_in_effect(
      true);
  get_dictionary_attack_info_reply_
      .set_dictionary_attack_lockout_seconds_remaining(789);
  EXPECT_TRUE(tpm_manager_utility_.GetDictionaryAttackInfo(
      &counter, &threshold, &lockout, &seconds_remaining));
  EXPECT_EQ(counter,
            get_dictionary_attack_info_reply_.dictionary_attack_counter());
  EXPECT_EQ(threshold,
            get_dictionary_attack_info_reply_.dictionary_attack_threshold());
  EXPECT_EQ(
      lockout,
      get_dictionary_attack_info_reply_.dictionary_attack_lockout_in_effect());
  EXPECT_EQ(seconds_remaining,
            get_dictionary_attack_info_reply_
                .dictionary_attack_lockout_seconds_remaining());
}

TEST_F(TpmManagerUtilityTest, GetDictionaryAttackInfoFail) {
  int counter = 0;
  int threshold = 0;
  bool lockout = false;
  int seconds_remaining = 0;

  get_dictionary_attack_info_reply_.set_status(
      tpm_manager::STATUS_DEVICE_ERROR);
  EXPECT_FALSE(tpm_manager_utility_.GetDictionaryAttackInfo(
      &counter, &threshold, &lockout, &seconds_remaining));

  get_dictionary_attack_info_reply_.set_status(
      tpm_manager::STATUS_NOT_AVAILABLE);
  EXPECT_FALSE(tpm_manager_utility_.GetDictionaryAttackInfo(
      &counter, &threshold, &lockout, &seconds_remaining));
}

TEST_F(TpmManagerUtilityTest, ResetDictionaryAttackLock) {
  reset_dictionary_attack_lock_reply_.set_status(tpm_manager::STATUS_SUCCESS);
  EXPECT_TRUE(tpm_manager_utility_.ResetDictionaryAttackLock());
}

TEST_F(TpmManagerUtilityTest, ResetDictionaryAttackLockFail) {
  reset_dictionary_attack_lock_reply_.set_status(
      tpm_manager::STATUS_DEVICE_ERROR);
  EXPECT_FALSE(tpm_manager_utility_.ResetDictionaryAttackLock());

  reset_dictionary_attack_lock_reply_.set_status(
      tpm_manager::STATUS_NOT_AVAILABLE);
  EXPECT_FALSE(tpm_manager_utility_.ResetDictionaryAttackLock());
}

TEST_F(TpmManagerUtilityTest, ClearStoredOwnerPassword) {
  clear_stored_owner_password_reply_.set_status(tpm_manager::STATUS_SUCCESS);
  EXPECT_TRUE(tpm_manager_utility_.ClearStoredOwnerPassword());
}

TEST_F(TpmManagerUtilityTest, ClearStoredOwnerPasswordFail) {
  clear_stored_owner_password_reply_.set_status(
      tpm_manager::STATUS_DEVICE_ERROR);
  EXPECT_FALSE(tpm_manager_utility_.ClearStoredOwnerPassword());

  clear_stored_owner_password_reply_.set_status(
      tpm_manager::STATUS_NOT_AVAILABLE);
  EXPECT_FALSE(tpm_manager_utility_.ClearStoredOwnerPassword());
}

TEST_F(TpmManagerUtilityTest, ExtraInitializationCall) {
  EXPECT_TRUE(tpm_manager_utility_.Initialize());
}

TEST_F(TpmManagerUtilityTest, OwnershipTakenSignal) {
  bool result_is_successful;
  bool result_has_received;
  LocalData result_local_data;

  // Tests the initial state.
  EXPECT_FALSE(tpm_manager_utility_.GetOwnershipTakenSignalStatus(
      &result_is_successful, &result_has_received, &result_local_data));

  // Tests the signal connection failure.
  tpm_manager_utility_.OnSignalConnected("", "", false);
  EXPECT_TRUE(tpm_manager_utility_.GetOwnershipTakenSignalStatus(
      &result_is_successful, &result_has_received, &result_local_data));
  EXPECT_FALSE(result_is_successful);

  // Tests the signal connection success.
  tpm_manager_utility_.OnSignalConnected("", "", true);
  EXPECT_TRUE(tpm_manager_utility_.GetOwnershipTakenSignalStatus(
      &result_is_successful, &result_has_received, &result_local_data));
  EXPECT_TRUE(result_is_successful);
  EXPECT_FALSE(result_has_received);

  OwnershipTakenSignal signal;
  signal.mutable_local_data()->set_owner_password("owner password");
  signal.mutable_local_data()->set_endorsement_password("endorsement password");
  tpm_manager_utility_.OnOwnershipTaken(signal);
  EXPECT_TRUE(tpm_manager_utility_.GetOwnershipTakenSignalStatus(
      &result_is_successful, &result_has_received, &result_local_data));
  EXPECT_TRUE(result_is_successful);
  EXPECT_TRUE(result_has_received);
  EXPECT_EQ(result_local_data.SerializeAsString(),
            signal.local_data().SerializeAsString());

  // Tests if the null parameters break the code.
  EXPECT_TRUE(tpm_manager_utility_.GetOwnershipTakenSignalStatus(
      nullptr, nullptr, nullptr));
}

void TpmManagerUtilityTest::RunDefineSpaceTest(bool write_define,
                                               bool bind_to_pcr0,
                                               bool firmware_readable,
                                               tpm_manager::NvramResult result,
                                               bool expect_success) {
  constexpr uint32_t kNvIndex = 0x0123456;
  constexpr size_t kSize = 0x1234;

  tpm_manager::DefineSpaceRequest request;

  tpm_manager::DefineSpaceReply reply;
  reply.set_result(result);

  EXPECT_CALL(mock_tpm_nvram_, DefineSpaceAsync(_, _, _, _))
      .WillOnce(Invoke([&](auto req, auto callback, auto, auto) {
        request = req;
        std::move(callback).Run(reply);
      }));
  std::string output;
  EXPECT_EQ(expect_success,
            tpm_manager_utility_.DefineSpace(kNvIndex, kSize, write_define,
                                             bind_to_pcr0, firmware_readable));

  EXPECT_EQ(kNvIndex, request.index());
  EXPECT_EQ(kSize, request.size());
  EXPECT_EQ(bind_to_pcr0, request.policy() == tpm_manager::NVRAM_POLICY_PCR0);
  std::set<tpm_manager::NvramSpaceAttribute> attrs;
  for (auto attr : request.attributes()) {
    EXPECT_TRUE(attrs.insert(tpm_manager::NvramSpaceAttribute(attr)).second);
  }
  EXPECT_EQ(
      write_define,
      attrs.find(tpm_manager::NVRAM_PERSISTENT_WRITE_LOCK) != attrs.end());
  EXPECT_EQ(firmware_readable,
            attrs.find(tpm_manager::NVRAM_PLATFORM_READ) != attrs.end());
}

TEST_F(TpmManagerUtilityTest, DefineSpace) {
  for (bool write_define : {true, false}) {
    for (bool bind_to_pcr0 : {true, false}) {
      for (bool firmware_readable : {true, false}) {
        RunDefineSpaceTest(write_define, bind_to_pcr0, firmware_readable,
                           tpm_manager::NVRAM_RESULT_SUCCESS,
                           true /* success */);
      }
    }
  }
}

TEST_F(TpmManagerUtilityTest, DefineSpaceDeviceError) {
  RunDefineSpaceTest(false, false, false,
                     tpm_manager::NVRAM_RESULT_DEVICE_ERROR,
                     false /* success */);
}

TEST_F(TpmManagerUtilityTest, DestroySpace) {
  destroy_space_reply_.set_result(tpm_manager::NVRAM_RESULT_SUCCESS);
  EXPECT_TRUE(tpm_manager_utility_.DestroySpace(0x123456));
}

TEST_F(TpmManagerUtilityTest, DestroySpaceFail) {
  destroy_space_reply_.set_result(tpm_manager::NVRAM_RESULT_DEVICE_ERROR);
  EXPECT_FALSE(tpm_manager_utility_.DestroySpace(0x123456));
  destroy_space_reply_.set_result(tpm_manager::NVRAM_RESULT_OPERATION_DISABLED);
  EXPECT_FALSE(tpm_manager_utility_.DestroySpace(0x123456));
  destroy_space_reply_.set_result(tpm_manager::NVRAM_RESULT_ACCESS_DENIED);
  EXPECT_FALSE(tpm_manager_utility_.DestroySpace(0x123456));
}

void TpmManagerUtilityTest::RunReadSpaceTest(bool use_owner_auth,
                                             tpm_manager::NvramResult result,
                                             std::optional<std::string> value,
                                             bool expect_success) {
  constexpr uint32_t kNvIndex = 0x0123456;
  tpm_manager::ReadSpaceRequest request;

  tpm_manager::ReadSpaceReply reply;
  reply.set_result(result);
  if (value) {
    reply.set_data(*value);
  }

  EXPECT_CALL(mock_tpm_nvram_, ReadSpaceAsync(_, _, _, _))
      .WillOnce(Invoke([&](auto req, auto callback, auto, auto) {
        request = req;
        std::move(callback).Run(reply);
      }));

  std::string output;
  EXPECT_EQ(expect_success,
            tpm_manager_utility_.ReadSpace(kNvIndex, use_owner_auth, &output));

  EXPECT_EQ(kNvIndex, request.index());
  EXPECT_EQ(use_owner_auth, request.use_owner_authorization());

  if (value) {
    EXPECT_EQ(output, *value);
  }
}

TEST_F(TpmManagerUtilityTest, ReadSpace) {
  RunReadSpaceTest(false /* owner auth */, tpm_manager::NVRAM_RESULT_SUCCESS,
                   "notarealnvramspace", true /* success */);
}

TEST_F(TpmManagerUtilityTest, ReadSpaceOwnerAuth) {
  RunReadSpaceTest(true /* owner auth */, tpm_manager::NVRAM_RESULT_SUCCESS,
                   "notarealnvramspace", true /* success */);
}

TEST_F(TpmManagerUtilityTest, ReadSpaceNvRamSpaceDoesNotExist) {
  RunReadSpaceTest(false /* owner auth */,
                   tpm_manager::NVRAM_RESULT_SPACE_DOES_NOT_EXIST, {},
                   false /* success */);
}

TEST_F(TpmManagerUtilityTest, ReadSpaceError) {
  RunReadSpaceTest(false /* owner auth */,
                   tpm_manager::NVRAM_RESULT_ACCESS_DENIED, {},
                   false /* success */);
}

void TpmManagerUtilityTest::RunWriteSpaceTest(bool use_owner_auth,
                                              tpm_manager::NvramResult result,
                                              bool expect_success) {
  constexpr uint32_t kNvIndex = 0x0123456;
  const std::string kData = "write space test";
  tpm_manager::WriteSpaceRequest request;

  tpm_manager::WriteSpaceReply reply;
  reply.set_result(result);

  EXPECT_CALL(mock_tpm_nvram_, WriteSpaceAsync(_, _, _, _))
      .WillOnce(Invoke([&](auto req, auto callback, auto, auto) {
        request = req;
        std::move(callback).Run(reply);
      }));

  EXPECT_EQ(expect_success,
            tpm_manager_utility_.WriteSpace(kNvIndex, kData, use_owner_auth));

  EXPECT_EQ(kNvIndex, request.index());
  EXPECT_EQ(use_owner_auth, request.use_owner_authorization());
}

TEST_F(TpmManagerUtilityTest, WriteSpace) {
  RunWriteSpaceTest(false /* owner auth */, tpm_manager::NVRAM_RESULT_SUCCESS,
                    true /* success */);
}

TEST_F(TpmManagerUtilityTest, WriteSpaceOwnerAuth) {
  RunWriteSpaceTest(true /* owner auth */, tpm_manager::NVRAM_RESULT_SUCCESS,
                    true /* success */);
}

TEST_F(TpmManagerUtilityTest, WriteSpaceNvRamSpaceDoesNotExist) {
  RunWriteSpaceTest(false /* owner auth */,
                    tpm_manager::NVRAM_RESULT_SPACE_DOES_NOT_EXIST,
                    false /* success */);
}

TEST_F(TpmManagerUtilityTest, WriteSpaceError) {
  RunWriteSpaceTest(false /* owner auth */,
                    tpm_manager::NVRAM_RESULT_ACCESS_DENIED,
                    false /* success */);
}

TEST_F(TpmManagerUtilityTest, ListSpaces) {
  const std::vector<uint32_t> expect = {1, 5, 7};
  std::vector<uint32_t> result;
  list_spaces_reply_.set_result(tpm_manager::NVRAM_RESULT_SUCCESS);
  for (uint32_t index : expect) {
    list_spaces_reply_.add_index_list(index);
  }
  EXPECT_TRUE(tpm_manager_utility_.ListSpaces(&result));
  EXPECT_EQ(result, expect);
}

TEST_F(TpmManagerUtilityTest, ListSpacesFail) {
  std::vector<uint32_t> result;
  list_spaces_reply_.set_result(tpm_manager::NVRAM_RESULT_DEVICE_ERROR);
  EXPECT_FALSE(tpm_manager_utility_.ListSpaces(&result));
  list_spaces_reply_.set_result(tpm_manager::NVRAM_RESULT_ACCESS_DENIED);
  EXPECT_FALSE(tpm_manager_utility_.ListSpaces(&result));
}

TEST_F(TpmManagerUtilityTest, GetSpaceInfo) {
  constexpr uint32_t kSize = 0x9487;
  constexpr bool kReadLocked = true;
  constexpr bool kWriteLocked = true;
  const std::vector<NvramSpaceAttribute> kAllAttributes{
      NVRAM_READ_AUTHORIZATION, NVRAM_OWNER_WRITE};
  get_space_info_reply_.set_result(tpm_manager::NVRAM_RESULT_SUCCESS);
  get_space_info_reply_.set_size(kSize);
  get_space_info_reply_.set_is_read_locked(kReadLocked);
  get_space_info_reply_.set_is_write_locked(kWriteLocked);
  for (auto attr : kAllAttributes) {
    get_space_info_reply_.add_attributes(attr);
  }
  uint32_t size = 0;
  bool is_read_locked = false;
  bool is_write_locked = false;
  std::vector<NvramSpaceAttribute> attributes;
  EXPECT_TRUE(tpm_manager_utility_.GetSpaceInfo(
      0x123456, &size, &is_read_locked, &is_write_locked, &attributes));
  EXPECT_EQ(kSize, size);
  EXPECT_EQ(kReadLocked, is_read_locked);
  EXPECT_EQ(kWriteLocked, is_write_locked);
  EXPECT_THAT(attributes, ElementsAreArray(kAllAttributes));
}

TEST_F(TpmManagerUtilityTest, GetSpaceInfoNoOutputAttributes) {
  constexpr uint32_t kSize = 0x9487;
  constexpr bool kReadLocked = true;
  constexpr bool kWriteLocked = true;
  get_space_info_reply_.set_result(tpm_manager::NVRAM_RESULT_SUCCESS);
  get_space_info_reply_.set_size(kSize);
  get_space_info_reply_.set_is_read_locked(kReadLocked);
  get_space_info_reply_.set_is_write_locked(kWriteLocked);
  get_space_info_reply_.add_attributes(NVRAM_READ_AUTHORIZATION);
  uint32_t size = 0;
  bool is_read_locked = false;
  bool is_write_locked = false;
  EXPECT_TRUE(tpm_manager_utility_.GetSpaceInfo(
      0x123456, &size, &is_read_locked, &is_write_locked, nullptr));
  EXPECT_EQ(kSize, size);
  EXPECT_EQ(kReadLocked, is_read_locked);
  EXPECT_EQ(kWriteLocked, is_write_locked);
}

TEST_F(TpmManagerUtilityTest, GetSpaceInfoFail) {
  uint32_t size = 0;
  bool is_read_locked = false;
  bool is_write_locked = false;
  std::vector<NvramSpaceAttribute> attributes;
  get_space_info_reply_.set_result(tpm_manager::NVRAM_RESULT_DEVICE_ERROR);
  EXPECT_FALSE(tpm_manager_utility_.GetSpaceInfo(
      0x123456, &size, &is_read_locked, &is_write_locked, &attributes));
  get_space_info_reply_.set_result(tpm_manager::NVRAM_RESULT_ACCESS_DENIED);
  EXPECT_FALSE(tpm_manager_utility_.GetSpaceInfo(
      0x123456, &size, &is_read_locked, &is_write_locked, &attributes));
}

TEST_F(TpmManagerUtilityTest, LockSpace) {
  tpm_manager::LockSpaceRequest request;
  lock_space_reply_.set_result(tpm_manager::NVRAM_RESULT_SUCCESS);
  EXPECT_CALL(mock_tpm_nvram_, LockSpaceAsync(_, _, _, _))
      .WillOnce(Invoke([&](auto req, auto callback, auto, auto) {
        request = req;
        std::move(callback).Run(lock_space_reply_);
      }));
  EXPECT_TRUE(tpm_manager_utility_.LockSpace(0x123456));
  EXPECT_TRUE(request.lock_write());
  EXPECT_FALSE(request.lock_read());
}

TEST_F(TpmManagerUtilityTest, LockSpaceFail) {
  lock_space_reply_.set_result(tpm_manager::NVRAM_RESULT_DEVICE_ERROR);
  EXPECT_FALSE(tpm_manager_utility_.LockSpace(0x123456));
  lock_space_reply_.set_result(tpm_manager::NVRAM_RESULT_OPERATION_DISABLED);
  EXPECT_FALSE(tpm_manager_utility_.LockSpace(0x123456));
  lock_space_reply_.set_result(tpm_manager::NVRAM_RESULT_ACCESS_DENIED);
  EXPECT_FALSE(tpm_manager_utility_.LockSpace(0x123456));
}

}  // namespace tpm_manager
