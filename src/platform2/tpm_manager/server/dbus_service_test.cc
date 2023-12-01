// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iterator>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <brillo/dbus/dbus_object_test_helpers.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_exported_object.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <tpm_manager-client/tpm_manager/dbus-constants.h>

#include "tpm_manager/server/dbus_service.h"
#include "tpm_manager/server/mock_local_data_store.h"
#include "tpm_manager/server/mock_tpm_nvram_interface.h"
#include "tpm_manager/server/mock_tpm_ownership_interface.h"
#include "tpm_manager/server/tpm_nvram_dbus_interface.h"

using testing::_;
using testing::DoAll;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;
using testing::StrictMock;
using testing::WithArgs;

namespace tpm_manager {

class DBusServiceTest : public testing::Test {
 public:
  ~DBusServiceTest() override = default;
  void SetUp() override {
    dbus::Bus::Options options;
    mock_bus_ = new NiceMock<dbus::MockBus>(options);
    dbus::ObjectPath path(kTpmManagerServicePath);
    mock_exported_object_ =
        new NiceMock<dbus::MockExportedObject>(mock_bus_.get(), path);
    ON_CALL(*mock_bus_, GetExportedObject(path))
        .WillByDefault(Return(mock_exported_object_.get()));
    dbus_service_.reset(new DBusService(mock_bus_, &mock_nvram_service_,
                                        &mock_ownership_service_,
                                        &mock_data_store_));
  }

  void RegisterDBusObjectsAsync() {
    scoped_refptr<brillo::dbus_utils::AsyncEventSequencer> sequencer(
        new brillo::dbus_utils::AsyncEventSequencer());
    dbus_service_->RegisterDBusObjectsAsync(sequencer.get());
  }

  template <typename RequestProtobufType, typename ReplyProtobufType>
  void ExecuteMethod(const std::string& method_name,
                     const RequestProtobufType& request,
                     ReplyProtobufType* reply,
                     const std::string& interface) {
    std::unique_ptr<dbus::MethodCall> call =
        CreateMethodCall(method_name, interface);
    dbus::MessageWriter writer(call.get());
    writer.AppendProtoAsArrayOfBytes(request);
    auto response = brillo::dbus_utils::testing::CallMethod(
        *dbus_service_->dbus_object_, call.get());
    dbus::MessageReader reader(response.get());
    EXPECT_TRUE(reader.PopArrayOfBytesAsProto(reply));
  }

 protected:
  std::unique_ptr<dbus::MethodCall> CreateMethodCall(
      const std::string& method_name, const std::string& interface) {
    std::unique_ptr<dbus::MethodCall> call(
        new dbus::MethodCall(interface, method_name));
    call->SetSerial(1);
    return call;
  }

  scoped_refptr<dbus::MockBus> mock_bus_;
  scoped_refptr<dbus::MockExportedObject> mock_exported_object_;
  StrictMock<MockLocalDataStore> mock_data_store_;
  StrictMock<MockTpmNvramInterface> mock_nvram_service_;
  StrictMock<MockTpmOwnershipInterface> mock_ownership_service_;
  std::unique_ptr<DBusService> dbus_service_;
};

TEST_F(DBusServiceTest, GetTpmStatus) {
  RegisterDBusObjectsAsync();

  GetTpmStatusRequest request;
  EXPECT_CALL(mock_ownership_service_, GetTpmStatus(_, _))
      .WillOnce(
          Invoke([](const GetTpmStatusRequest& request,
                    TpmOwnershipInterface::GetTpmStatusCallback callback) {
            GetTpmStatusReply reply;
            reply.set_status(STATUS_SUCCESS);
            reply.set_enabled(true);
            reply.set_owned(true);
            std::move(callback).Run(reply);
          }));
  GetTpmStatusReply reply;
  ExecuteMethod(kGetTpmStatus, request, &reply, kTpmManagerInterface);
  EXPECT_EQ(STATUS_SUCCESS, reply.status());
  EXPECT_TRUE(reply.enabled());
  EXPECT_TRUE(reply.owned());
}

TEST_F(DBusServiceTest, GetTpmNonsensitiveStatus) {
  RegisterDBusObjectsAsync();

  GetTpmNonsensitiveStatusRequest request;
  EXPECT_CALL(mock_ownership_service_, GetTpmNonsensitiveStatus(_, _))
      .WillOnce(Invoke(
          [](const GetTpmNonsensitiveStatusRequest& request,
             TpmOwnershipInterface::GetTpmNonsensitiveStatusCallback callback) {
            GetTpmNonsensitiveStatusReply reply;
            reply.set_status(STATUS_SUCCESS);
            reply.set_is_enabled(true);
            reply.set_is_owned(true);
            reply.set_is_owner_password_present(true);
            reply.set_has_reset_lock_permissions(true);
            std::move(callback).Run(reply);
          }));
  GetTpmNonsensitiveStatusReply reply;
  ExecuteMethod(kGetTpmNonsensitiveStatus, request, &reply,
                kTpmManagerInterface);
  EXPECT_EQ(STATUS_SUCCESS, reply.status());
  EXPECT_TRUE(reply.is_enabled());
  EXPECT_TRUE(reply.is_owned());
  EXPECT_TRUE(reply.is_owner_password_present());
  EXPECT_TRUE(reply.has_reset_lock_permissions());
}

TEST_F(DBusServiceTest, GetVersionInfo) {
  RegisterDBusObjectsAsync();

  GetVersionInfoReply expected_version_info;
  expected_version_info.set_status(STATUS_SUCCESS);
  expected_version_info.set_family(1);
  expected_version_info.set_spec_level(2);
  expected_version_info.set_manufacturer(3);
  expected_version_info.set_tpm_model(4);
  expected_version_info.set_firmware_version(5);
  expected_version_info.set_vendor_specific("ab");

  GetVersionInfoRequest request;
  EXPECT_CALL(mock_ownership_service_, GetVersionInfo(_, _))
      .WillOnce(
          Invoke([&expected_version_info](
                     const GetVersionInfoRequest& request,
                     TpmOwnershipInterface::GetVersionInfoCallback callback) {
            std::move(callback).Run(expected_version_info);
          }));

  GetVersionInfoReply actual_version_info;
  ExecuteMethod(kGetVersionInfo, request, &actual_version_info,
                kTpmManagerInterface);
  EXPECT_EQ(actual_version_info.SerializeAsString(),
            expected_version_info.SerializeAsString());
}

TEST_F(DBusServiceTest, GetDictionaryAttackInfo) {
  RegisterDBusObjectsAsync();

  GetDictionaryAttackInfoRequest request;
  EXPECT_CALL(mock_ownership_service_, GetDictionaryAttackInfo(_, _))
      .WillOnce(Invoke(
          [](const GetDictionaryAttackInfoRequest& request,
             TpmOwnershipInterface::GetDictionaryAttackInfoCallback callback) {
            GetDictionaryAttackInfoReply reply;
            reply.set_status(STATUS_SUCCESS);
            reply.set_dictionary_attack_counter(3);
            reply.set_dictionary_attack_threshold(4);
            reply.set_dictionary_attack_lockout_in_effect(true);
            reply.set_dictionary_attack_lockout_seconds_remaining(5);
            std::move(callback).Run(reply);
          }));
  GetDictionaryAttackInfoReply reply;
  ExecuteMethod(kGetDictionaryAttackInfo, request, &reply,
                kTpmManagerInterface);
  EXPECT_EQ(STATUS_SUCCESS, reply.status());
  EXPECT_EQ(3, reply.dictionary_attack_counter());
  EXPECT_EQ(4, reply.dictionary_attack_threshold());
  EXPECT_TRUE(reply.dictionary_attack_lockout_in_effect());
  EXPECT_EQ(5, reply.dictionary_attack_lockout_seconds_remaining());
}

TEST_F(DBusServiceTest, ResetDictionaryAttackLock) {
  RegisterDBusObjectsAsync();

  ResetDictionaryAttackLockRequest request;
  EXPECT_CALL(mock_ownership_service_, ResetDictionaryAttackLock(_, _))
      .WillOnce(
          Invoke([](const ResetDictionaryAttackLockRequest& request,
                    TpmOwnershipInterface::ResetDictionaryAttackLockCallback
                        callback) {
            ResetDictionaryAttackLockReply reply;
            reply.set_status(STATUS_SUCCESS);
            std::move(callback).Run(reply);
          }));
  ResetDictionaryAttackLockReply reply;
  ExecuteMethod(kResetDictionaryAttackLock, request, &reply,
                kTpmManagerInterface);
  EXPECT_EQ(STATUS_SUCCESS, reply.status());
}

TEST_F(DBusServiceTest, TakeOwnership) {
  RegisterDBusObjectsAsync();

  EXPECT_CALL(mock_ownership_service_, TakeOwnership(_, _))
      .WillOnce(
          Invoke([](const TakeOwnershipRequest& request,
                    TpmOwnershipInterface::TakeOwnershipCallback callback) {
            TakeOwnershipReply reply;
            reply.set_status(STATUS_SUCCESS);
            std::move(callback).Run(reply);
          }));
  TakeOwnershipRequest request;
  TakeOwnershipReply reply;
  ExecuteMethod(kTakeOwnership, request, &reply, kTpmManagerInterface);
  EXPECT_EQ(STATUS_SUCCESS, reply.status());
}

TEST_F(DBusServiceTest, RemoveOwnerDependency) {
  RegisterDBusObjectsAsync();

  std::string owner_dependency("owner_dependency");
  RemoveOwnerDependencyRequest request;
  request.set_owner_dependency(owner_dependency);
  EXPECT_CALL(mock_ownership_service_, RemoveOwnerDependency(_, _))
      .WillOnce(Invoke(
          [&owner_dependency](
              const RemoveOwnerDependencyRequest& request,
              TpmOwnershipInterface::RemoveOwnerDependencyCallback callback) {
            EXPECT_TRUE(request.has_owner_dependency());
            EXPECT_EQ(owner_dependency, request.owner_dependency());
            RemoveOwnerDependencyReply reply;
            reply.set_status(STATUS_SUCCESS);
            std::move(callback).Run(reply);
          }));
  RemoveOwnerDependencyReply reply;
  ExecuteMethod(kRemoveOwnerDependency, request, &reply, kTpmManagerInterface);
  EXPECT_EQ(STATUS_SUCCESS, reply.status());
}

TEST_F(DBusServiceTest, ClearStoredOwnerPassword) {
  RegisterDBusObjectsAsync();

  ClearStoredOwnerPasswordRequest request;
  EXPECT_CALL(mock_ownership_service_, ClearStoredOwnerPassword(_, _))
      .WillOnce(Invoke(
          [](const ClearStoredOwnerPasswordRequest& request,
             TpmOwnershipInterface::ClearStoredOwnerPasswordCallback callback) {
            ClearStoredOwnerPasswordReply reply;
            reply.set_status(STATUS_SUCCESS);
            std::move(callback).Run(reply);
          }));
  ClearStoredOwnerPasswordReply reply;
  ExecuteMethod(kClearStoredOwnerPassword, request, &reply,
                kTpmManagerInterface);
  EXPECT_EQ(STATUS_SUCCESS, reply.status());
}

TEST_F(DBusServiceTest, DefineSpace) {
  RegisterDBusObjectsAsync();

  uint32_t nvram_index = 5;
  size_t nvram_length = 32;
  DefineSpaceRequest request;
  request.set_index(nvram_index);
  request.set_size(nvram_length);
  EXPECT_CALL(mock_nvram_service_, DefineSpace(_, _))
      .WillOnce(Invoke([nvram_index, nvram_length](
                           const DefineSpaceRequest& request,
                           TpmNvramInterface::DefineSpaceCallback callback) {
        EXPECT_TRUE(request.has_index());
        EXPECT_EQ(nvram_index, request.index());
        EXPECT_TRUE(request.has_size());
        EXPECT_EQ(nvram_length, request.size());
        DefineSpaceReply reply;
        reply.set_result(NVRAM_RESULT_SUCCESS);
        std::move(callback).Run(reply);
      }));
  DefineSpaceReply reply;
  ExecuteMethod(kDefineSpace, request, &reply, kTpmNvramInterface);
  EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
}

TEST_F(DBusServiceTest, DestroySpace) {
  RegisterDBusObjectsAsync();

  uint32_t nvram_index = 5;
  DestroySpaceRequest request;
  request.set_index(nvram_index);
  EXPECT_CALL(mock_nvram_service_, DestroySpace(_, _))
      .WillOnce(Invoke(
          [nvram_index](const DestroySpaceRequest& request,
                        TpmNvramInterface::DestroySpaceCallback callback) {
            EXPECT_TRUE(request.has_index());
            EXPECT_EQ(nvram_index, request.index());
            DestroySpaceReply reply;
            reply.set_result(NVRAM_RESULT_SUCCESS);
            std::move(callback).Run(reply);
          }));
  DestroySpaceReply reply;
  ExecuteMethod(kDestroySpace, request, &reply, kTpmNvramInterface);
  EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
}

TEST_F(DBusServiceTest, WriteSpace) {
  RegisterDBusObjectsAsync();

  uint32_t nvram_index = 5;
  std::string nvram_data("nvram_data");
  WriteSpaceRequest request;
  request.set_index(nvram_index);
  request.set_data(nvram_data);
  EXPECT_CALL(mock_nvram_service_, WriteSpace(_, _))
      .WillOnce(Invoke([nvram_index, nvram_data](
                           const WriteSpaceRequest& request,
                           TpmNvramInterface::WriteSpaceCallback callback) {
        EXPECT_TRUE(request.has_index());
        EXPECT_EQ(nvram_index, request.index());
        EXPECT_TRUE(request.has_data());
        EXPECT_EQ(nvram_data, request.data());
        WriteSpaceReply reply;
        reply.set_result(NVRAM_RESULT_SUCCESS);
        std::move(callback).Run(reply);
      }));
  WriteSpaceReply reply;
  ExecuteMethod(kWriteSpace, request, &reply, kTpmNvramInterface);
  EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
}

TEST_F(DBusServiceTest, ReadSpace) {
  RegisterDBusObjectsAsync();

  uint32_t nvram_index = 5;
  std::string nvram_data("nvram_data");
  ReadSpaceRequest request;
  request.set_index(nvram_index);
  EXPECT_CALL(mock_nvram_service_, ReadSpace(_, _))
      .WillOnce(Invoke([nvram_index, nvram_data](
                           const ReadSpaceRequest& request,
                           TpmNvramInterface::ReadSpaceCallback callback) {
        EXPECT_TRUE(request.has_index());
        EXPECT_EQ(nvram_index, request.index());
        ReadSpaceReply reply;
        reply.set_result(NVRAM_RESULT_SUCCESS);
        reply.set_data(nvram_data);
        std::move(callback).Run(reply);
      }));
  ReadSpaceReply reply;
  ExecuteMethod(kReadSpace, request, &reply, kTpmNvramInterface);
  EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
  EXPECT_TRUE(reply.has_data());
  EXPECT_EQ(nvram_data, reply.data());
}

TEST_F(DBusServiceTest, LockSpace) {
  RegisterDBusObjectsAsync();

  uint32_t nvram_index = 5;
  LockSpaceRequest request;
  request.set_index(nvram_index);
  request.set_lock_read(true);
  request.set_lock_write(true);
  EXPECT_CALL(mock_nvram_service_, LockSpace(_, _))
      .WillOnce(
          Invoke([nvram_index](const LockSpaceRequest& request,
                               TpmNvramInterface::LockSpaceCallback callback) {
            EXPECT_TRUE(request.has_index());
            EXPECT_EQ(nvram_index, request.index());
            EXPECT_TRUE(request.lock_read());
            EXPECT_TRUE(request.lock_write());
            LockSpaceReply reply;
            reply.set_result(NVRAM_RESULT_SUCCESS);
            std::move(callback).Run(reply);
          }));
  LockSpaceReply reply;
  ExecuteMethod(kLockSpace, request, &reply, kTpmNvramInterface);
  EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
}

TEST_F(DBusServiceTest, ListSpaces) {
  RegisterDBusObjectsAsync();

  constexpr uint32_t nvram_index_list[] = {3, 4, 5};
  ListSpacesRequest request;
  EXPECT_CALL(mock_nvram_service_, ListSpaces(_, _))
      .WillOnce(Invoke(
          [nvram_index_list](const ListSpacesRequest& request,
                             TpmNvramInterface::ListSpacesCallback callback) {
            ListSpacesReply reply;
            reply.set_result(NVRAM_RESULT_SUCCESS);
            for (auto index : nvram_index_list) {
              reply.add_index_list(index);
            }
            std::move(callback).Run(reply);
          }));
  ListSpacesReply reply;
  ExecuteMethod(kListSpaces, request, &reply, kTpmNvramInterface);
  EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
  EXPECT_EQ(std::size(nvram_index_list), reply.index_list_size());
  for (size_t i = 0; i < 3; i++) {
    EXPECT_EQ(nvram_index_list[i], reply.index_list(i));
  }
}

TEST_F(DBusServiceTest, GetSpaceInfo) {
  RegisterDBusObjectsAsync();

  uint32_t nvram_index = 5;
  size_t nvram_size = 32;
  GetSpaceInfoRequest request;
  request.set_index(nvram_index);
  EXPECT_CALL(mock_nvram_service_, GetSpaceInfo(_, _))
      .WillOnce(Invoke([nvram_index, nvram_size](
                           const GetSpaceInfoRequest& request,
                           TpmNvramInterface::GetSpaceInfoCallback callback) {
        EXPECT_TRUE(request.has_index());
        EXPECT_EQ(nvram_index, request.index());
        GetSpaceInfoReply reply;
        reply.set_result(NVRAM_RESULT_SUCCESS);
        reply.set_size(nvram_size);
        reply.set_is_read_locked(true);
        reply.set_is_write_locked(true);
        std::move(callback).Run(reply);
      }));
  GetSpaceInfoReply reply;
  ExecuteMethod(kGetSpaceInfo, request, &reply, kTpmNvramInterface);
  EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
  EXPECT_TRUE(reply.has_size());
  EXPECT_EQ(nvram_size, reply.size());
  EXPECT_TRUE(reply.is_read_locked());
  EXPECT_TRUE(reply.is_write_locked());
}

TEST_F(DBusServiceTest, SendOwnershipTakenSignalAfterNotification) {
  LocalData local_data;
  EXPECT_CALL(mock_data_store_, Read(_))
      .WillRepeatedly(DoAll(SetArgPointee<0>(local_data), Return(true)));

  RegisterDBusObjectsAsync();

  EXPECT_FALSE(dbus_service_->MaybeSendOwnershipTakenSignal());
  dbus_service_->NotifyOwnershipIsTaken();
  EXPECT_TRUE(dbus_service_->MaybeSendOwnershipTakenSignal());
}

TEST_F(DBusServiceTest, DISABLED_SendOwnershipTakenSignalError) {
  ON_CALL(*mock_bus_, GetExportedObject(_)).WillByDefault(Return(nullptr));

  RegisterDBusObjectsAsync();
  dbus_service_->NotifyOwnershipIsTaken();

  EXPECT_FALSE(dbus_service_->MaybeSendOwnershipTakenSignal());
}

TEST_F(DBusServiceTest, SendOwnershipTakenSignalAfterRegistration) {
  LocalData local_data;
  EXPECT_CALL(mock_data_store_, Read(_))
      .WillRepeatedly(DoAll(SetArgPointee<0>(local_data), Return(true)));

  dbus_service_->NotifyOwnershipIsTaken();
  EXPECT_FALSE(dbus_service_->MaybeSendOwnershipTakenSignal());

  RegisterDBusObjectsAsync();

  EXPECT_TRUE(dbus_service_->MaybeSendOwnershipTakenSignal());
}

}  // namespace tpm_manager
