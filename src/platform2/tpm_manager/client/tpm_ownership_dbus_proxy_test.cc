// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/client/tpm_ownership_dbus_proxy.h"

#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <brillo/dbus/dbus_param_writer.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "tpm_manager/client/mock_tpm_ownership_signal_handler.h"
#include "tpm_manager-client/tpm_manager/dbus-constants.h"

using testing::_;
using testing::DoAll;
using testing::Invoke;
using testing::SaveArg;
using testing::StrictMock;
using testing::WithArgs;

ACTION_TEMPLATE(MovePointee,
                HAS_1_TEMPLATE_PARAMS(int, k),
                AND_1_VALUE_PARAMS(pointer)) {
  *pointer = std::move(*(::std::get<k>(args)));
}

namespace tpm_manager {

class TpmOwnershipDBusProxyTest : public testing::Test {
 public:
  ~TpmOwnershipDBusProxyTest() override = default;
  void SetUp() override {
    mock_object_proxy_ = new StrictMock<dbus::MockObjectProxy>(
        nullptr, "", dbus::ObjectPath(kTpmManagerServicePath));
    proxy_.set_object_proxy(mock_object_proxy_.get());
  }

 protected:
  scoped_refptr<StrictMock<dbus::MockObjectProxy>> mock_object_proxy_;
  TpmOwnershipDBusProxy proxy_;
};

TEST_F(TpmOwnershipDBusProxyTest, ConnectToSignal) {
  MockTpmOwnershipTakenSignalHandler mock_signal_handler;
  // set up the signal here
  OwnershipTakenSignal expected_signal;
  OwnershipTakenSignal result_signal;
  expected_signal.mutable_local_data()->set_owner_password("owner password");
  expected_signal.mutable_local_data()->set_endorsement_password(
      "endorsement password");
  dbus::ObjectProxy::SignalCallback ownership_taken_callback;
  dbus::ObjectProxy::OnConnectedCallback signal_connected_callback;
  EXPECT_CALL(
      *mock_object_proxy_,
      DoConnectToSignal(kTpmManagerInterface, kOwnershipTakenSignal, _, _))
      .WillOnce(DoAll(SaveArg<2>(&ownership_taken_callback),
                      MovePointee<3>(&signal_connected_callback)));
  EXPECT_CALL(mock_signal_handler, OnOwnershipTaken(_))
      .WillOnce(SaveArg<0>(&result_signal));
  EXPECT_CALL(
      mock_signal_handler,
      OnSignalConnected(kTpmManagerInterface, kOwnershipTakenSignal, true))
      .Times(1);

  proxy_.ConnectToSignal(&mock_signal_handler);
  dbus::Signal signal(kTpmManagerInterface, kOwnershipTakenSignal);
  dbus::MessageWriter writer(&signal);
  brillo::dbus_utils::DBusParamWriter::Append(&writer, expected_signal);
  ownership_taken_callback.Run(&signal);
  std::move(signal_connected_callback)
      .Run(kTpmManagerInterface, kOwnershipTakenSignal, true);
  EXPECT_EQ(expected_signal.SerializeAsString(),
            result_signal.SerializeAsString());
}

TEST_F(TpmOwnershipDBusProxyTest, GetTpmStatus) {
  auto fake_dbus_call =
      [](dbus::MethodCall* method_call,
         dbus::MockObjectProxy::ResponseCallback* response_callback) {
        // Verify request protobuf.
        dbus::MessageReader reader(method_call);
        GetTpmStatusRequest request;
        EXPECT_TRUE(reader.PopArrayOfBytesAsProto(&request));
        // Create reply protobuf.
        auto response = dbus::Response::CreateEmpty();
        dbus::MessageWriter writer(response.get());
        GetTpmStatusReply reply;
        reply.set_status(STATUS_SUCCESS);
        reply.set_enabled(true);
        reply.set_owned(true);
        writer.AppendProtoAsArrayOfBytes(reply);
        std::move(*response_callback).Run(response.get());
      };
  EXPECT_CALL(*mock_object_proxy_, DoCallMethodWithErrorCallback(_, _, _, _))
      .WillOnce(WithArgs<0, 2>(Invoke(fake_dbus_call)));

  // Set expectations on the outputs.
  int callback_count = 0;
  auto callback = [](int* callback_count, const GetTpmStatusReply& reply) {
    (*callback_count)++;
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.enabled());
    EXPECT_TRUE(reply.owned());
  };
  GetTpmStatusRequest request;
  proxy_.GetTpmStatus(request, base::BindOnce(callback, &callback_count));
  EXPECT_EQ(1, callback_count);
}

TEST_F(TpmOwnershipDBusProxyTest, GetTpmNonsensitiveStatus) {
  auto fake_dbus_call =
      [](dbus::MethodCall* method_call,
         dbus::MockObjectProxy::ResponseCallback* response_callback) {
        // Verify request protobuf.
        dbus::MessageReader reader(method_call);
        GetTpmNonsensitiveStatusRequest request;
        EXPECT_TRUE(reader.PopArrayOfBytesAsProto(&request));
        // Create reply protobuf.
        auto response = dbus::Response::CreateEmpty();
        dbus::MessageWriter writer(response.get());
        GetTpmNonsensitiveStatusReply reply;
        reply.set_status(STATUS_SUCCESS);
        reply.set_is_enabled(true);
        reply.set_is_owned(true);
        reply.set_is_owner_password_present(true);
        reply.set_has_reset_lock_permissions(true);
        writer.AppendProtoAsArrayOfBytes(reply);
        std::move(*response_callback).Run(response.get());
      };
  EXPECT_CALL(*mock_object_proxy_, DoCallMethodWithErrorCallback(_, _, _, _))
      .WillOnce(WithArgs<0, 2>(Invoke(fake_dbus_call)));

  // Set expectations on the outputs.
  int callback_count = 0;
  auto callback = [](int* callback_count,
                     const GetTpmNonsensitiveStatusReply& reply) {
    (*callback_count)++;
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.is_owned());
    EXPECT_TRUE(reply.is_enabled());
    EXPECT_TRUE(reply.is_owner_password_present());
    EXPECT_TRUE(reply.has_reset_lock_permissions());
  };
  GetTpmNonsensitiveStatusRequest request;
  proxy_.GetTpmNonsensitiveStatus(request,
                                  base::BindOnce(callback, &callback_count));
  EXPECT_EQ(1, callback_count);
}

TEST_F(TpmOwnershipDBusProxyTest, GetVersionInfo) {
  GetVersionInfoReply expected_version_info;
  expected_version_info.set_status(STATUS_SUCCESS);
  expected_version_info.set_family(1);
  expected_version_info.set_spec_level(2);
  expected_version_info.set_manufacturer(3);
  expected_version_info.set_tpm_model(4);
  expected_version_info.set_firmware_version(5);
  expected_version_info.set_vendor_specific("ab");

  auto fake_dbus_call =
      [&expected_version_info](
          dbus::MethodCall* method_call,
          dbus::MockObjectProxy::ResponseCallback* response_callback) {
        // Verify request protobuf.
        dbus::MessageReader reader(method_call);
        GetVersionInfoRequest request;
        EXPECT_TRUE(reader.PopArrayOfBytesAsProto(&request));
        // Create reply protobuf.
        auto response = dbus::Response::CreateEmpty();
        dbus::MessageWriter writer(response.get());
        writer.AppendProtoAsArrayOfBytes(expected_version_info);
        std::move(*response_callback).Run(response.get());
      };
  EXPECT_CALL(*mock_object_proxy_, DoCallMethodWithErrorCallback(_, _, _, _))
      .WillOnce(WithArgs<0, 2>(Invoke(fake_dbus_call)));

  // Set expectations on the outputs.
  int callback_count = 0;
  auto callback = [](const GetVersionInfoReply& expected_version_info,
                     int* callback_count,
                     const GetVersionInfoReply& actual_version_info) {
    (*callback_count)++;
    EXPECT_EQ(actual_version_info.SerializeAsString(),
              expected_version_info.SerializeAsString());
  };
  GetVersionInfoRequest request;
  proxy_.GetVersionInfo(request, base::BindOnce(callback, expected_version_info,
                                                &callback_count));
  EXPECT_EQ(1, callback_count);
}

TEST_F(TpmOwnershipDBusProxyTest, GetDictionaryAttackInfo) {
  auto fake_dbus_call =
      [](dbus::MethodCall* method_call,
         dbus::MockObjectProxy::ResponseCallback* response_callback) {
        // Verify request protobuf.
        dbus::MessageReader reader(method_call);
        GetDictionaryAttackInfoRequest request;
        EXPECT_TRUE(reader.PopArrayOfBytesAsProto(&request));
        // Create reply protobuf.
        auto response = dbus::Response::CreateEmpty();
        dbus::MessageWriter writer(response.get());
        GetDictionaryAttackInfoReply reply;
        reply.set_status(STATUS_SUCCESS);
        reply.set_dictionary_attack_counter(3);
        reply.set_dictionary_attack_threshold(4);
        reply.set_dictionary_attack_lockout_in_effect(true);
        reply.set_dictionary_attack_lockout_seconds_remaining(5);
        writer.AppendProtoAsArrayOfBytes(reply);
        std::move(*response_callback).Run(response.get());
      };
  EXPECT_CALL(*mock_object_proxy_, DoCallMethodWithErrorCallback(_, _, _, _))
      .WillOnce(WithArgs<0, 2>(Invoke(fake_dbus_call)));

  // Set expectations on the outputs.
  int callback_count = 0;
  auto callback = [](int* callback_count,
                     const GetDictionaryAttackInfoReply& reply) {
    (*callback_count)++;
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(3, reply.dictionary_attack_counter());
    EXPECT_EQ(4, reply.dictionary_attack_threshold());
    EXPECT_TRUE(reply.dictionary_attack_lockout_in_effect());
    EXPECT_EQ(5, reply.dictionary_attack_lockout_seconds_remaining());
  };
  GetDictionaryAttackInfoRequest request;
  proxy_.GetDictionaryAttackInfo(request,
                                 base::BindOnce(callback, &callback_count));
  EXPECT_EQ(1, callback_count);
}

TEST_F(TpmOwnershipDBusProxyTest, TakeOwnership) {
  auto fake_dbus_call =
      [](dbus::MethodCall* method_call,
         dbus::MockObjectProxy::ResponseCallback* response_callback) {
        // Verify request protobuf.
        dbus::MessageReader reader(method_call);
        TakeOwnershipRequest request;
        EXPECT_TRUE(reader.PopArrayOfBytesAsProto(&request));
        // Create reply protobuf.
        auto response = dbus::Response::CreateEmpty();
        dbus::MessageWriter writer(response.get());
        TakeOwnershipReply reply;
        reply.set_status(STATUS_SUCCESS);
        writer.AppendProtoAsArrayOfBytes(reply);
        std::move(*response_callback).Run(response.get());
      };
  EXPECT_CALL(*mock_object_proxy_, DoCallMethodWithErrorCallback(_, _, _, _))
      .WillOnce(WithArgs<0, 2>(Invoke(fake_dbus_call)));

  // Set expectations on the outputs.
  int callback_count = 0;
  auto callback = [](int* callback_count, const TakeOwnershipReply& reply) {
    (*callback_count)++;
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
  };
  TakeOwnershipRequest request;
  proxy_.TakeOwnership(request, base::BindOnce(callback, &callback_count));
  EXPECT_EQ(1, callback_count);
}

TEST_F(TpmOwnershipDBusProxyTest, RemoveOwnerDependency) {
  const std::string owner_dependency("owner");
  auto fake_dbus_call =
      [&owner_dependency](
          dbus::MethodCall* method_call,
          dbus::MockObjectProxy::ResponseCallback* response_callback) {
        // Verify request protobuf.
        dbus::MessageReader reader(method_call);
        RemoveOwnerDependencyRequest request;
        EXPECT_TRUE(reader.PopArrayOfBytesAsProto(&request));
        EXPECT_TRUE(request.has_owner_dependency());
        EXPECT_EQ(owner_dependency, request.owner_dependency());
        // Create reply protobuf.
        auto response = dbus::Response::CreateEmpty();
        dbus::MessageWriter writer(response.get());
        RemoveOwnerDependencyReply reply;
        reply.set_status(STATUS_SUCCESS);
        writer.AppendProtoAsArrayOfBytes(reply);
        std::move(*response_callback).Run(response.get());
      };
  EXPECT_CALL(*mock_object_proxy_, DoCallMethodWithErrorCallback(_, _, _, _))
      .WillOnce(WithArgs<0, 2>(Invoke(fake_dbus_call)));

  // Set expectations on the outputs.
  int callback_count = 0;
  auto callback = [](int* callback_count,
                     const RemoveOwnerDependencyReply& reply) {
    (*callback_count)++;
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
  };
  RemoveOwnerDependencyRequest request;
  request.set_owner_dependency(owner_dependency);
  proxy_.RemoveOwnerDependency(request,
                               base::BindOnce(callback, &callback_count));
  EXPECT_EQ(1, callback_count);
}

TEST_F(TpmOwnershipDBusProxyTest, ClearStoredOwnerPassword) {
  auto fake_dbus_call =
      [](dbus::MethodCall* method_call,
         dbus::MockObjectProxy::ResponseCallback* response_callback) {
        // Verify request protobuf.
        dbus::MessageReader reader(method_call);
        ClearStoredOwnerPasswordRequest request;
        EXPECT_TRUE(reader.PopArrayOfBytesAsProto(&request));
        // Create reply protobuf.
        auto response = dbus::Response::CreateEmpty();
        dbus::MessageWriter writer(response.get());
        ClearStoredOwnerPasswordReply reply;
        reply.set_status(STATUS_SUCCESS);
        writer.AppendProtoAsArrayOfBytes(reply);
        std::move(*response_callback).Run(response.get());
      };
  EXPECT_CALL(*mock_object_proxy_, DoCallMethodWithErrorCallback(_, _, _, _))
      .WillOnce(WithArgs<0, 2>(Invoke(fake_dbus_call)));

  // Set expectations on the outputs.
  int callback_count = 0;
  auto callback = [](int* callback_count,
                     const ClearStoredOwnerPasswordReply& reply) {
    (*callback_count)++;
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
  };
  ClearStoredOwnerPasswordRequest request;
  proxy_.ClearStoredOwnerPassword(request,
                                  base::BindOnce(callback, &callback_count));
  EXPECT_EQ(1, callback_count);
}

}  // namespace tpm_manager
