// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/trunks_dbus_proxy.h"

#include <memory>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/threading/thread.h>
#include <dbus/object_proxy.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/tpm_error/mock_tpm_error_uma_reporter.h>
#include <libhwsec-foundation/tpm_error/tpm_error_data.h>

#include "trunks/command_codes.h"
#include "trunks/dbus_interface.h"
#include "trunks/error_codes.h"
#include "trunks/mock_dbus_bus.h"
#include "trunks/trunks_interface.pb.h"

using testing::_;
using testing::NiceMock;
using testing::Return;
using testing::StrictMock;

namespace {

class FakeObjectProxy : public dbus::ObjectProxy {
 public:
  FakeObjectProxy()
      : dbus::ObjectProxy(
            nullptr, "", dbus::ObjectPath(trunks::kTrunksServicePath), 0) {}

  void CallMethodWithErrorCallback(
      dbus::MethodCall* method_call,
      int timeout_ms,
      dbus::ObjectProxy::ResponseCallback callback,
      dbus::ObjectProxy::ErrorCallback error_callback) override {
    dbus::ScopedDBusError error;
    std::unique_ptr<dbus::Response> response =
        CallMethodAndBlockWithErrorDetails(method_call, timeout_ms, &error);
    if (response) {
      std::move(callback).Run(response.get());
    } else {
      method_call->SetSerial(1);
      std::unique_ptr<dbus::ErrorResponse> error_response =
          dbus::ErrorResponse::FromMethodCall(method_call, "org.MyError",
                                              "Error message");
      std::move(error_callback).Run(error_response.get());
    }
  }

  std::unique_ptr<dbus::Response> CallMethodAndBlockWithErrorDetails(
      dbus::MethodCall* method_call,
      int /* timeout_ms */,
      dbus::ScopedDBusError* error) override {
    dbus::MessageReader reader(method_call);
    trunks::SendCommandRequest command_proto;
    brillo::dbus_utils::PopValueFromReader(&reader, &command_proto);
    last_command_ = command_proto.command();
    if (next_response_.empty()) {
      return std::unique_ptr<dbus::Response>();
    }
    std::unique_ptr<dbus::Response> dbus_response =
        dbus::Response::CreateEmpty();
    dbus::MessageWriter writer(dbus_response.get());
    trunks::SendCommandResponse response_proto;
    response_proto.set_response(next_response_);
    brillo::dbus_utils::AppendValueToWriter(&writer, response_proto);
    return dbus_response;
  }

  std::string next_response_;
  std::string last_command_;
};

}  // namespace

namespace trunks {

class TrunksDBusProxyTest : public testing::Test {
 public:
  TrunksDBusProxyTest() {
    proxy_.set_init_timeout(base::TimeDelta());
    proxy_.set_init_attempt_delay(base::TimeDelta());
    proxy_.set_uma_reporter_for_testing(uma_reporter_);
  }

  void SetUp() override {
    ON_CALL(*bus_, Connect()).WillByDefault(Return(true));
    ON_CALL(*bus_, GetObjectProxy(_, _))
        .WillByDefault(Return(object_proxy_.get()));
    ON_CALL(*bus_, GetServiceOwnerAndBlock(_, _))
        .WillByDefault(Return("test-service-owner"));
  }

  void set_next_response(const std::string& response) {
    object_proxy_->next_response_ = response;
  }
  std::string last_command() const {
    std::string last_command = object_proxy_->last_command_;
    object_proxy_->last_command_.clear();
    return last_command;
  }

 protected:
  scoped_refptr<FakeObjectProxy> object_proxy_ = new FakeObjectProxy();
  scoped_refptr<NiceMock<MockDBusBus>> bus_ = new NiceMock<MockDBusBus>();
  StrictMock<hwsec_foundation::MockTpmErrorUmaReporter>* uma_reporter_ =
      new StrictMock<hwsec_foundation::MockTpmErrorUmaReporter>();
  TrunksDBusProxy proxy_{bus_};
};

TEST_F(TrunksDBusProxyTest, InitSuccess) {
  EXPECT_CALL(*bus_, GetServiceOwnerAndBlock(_, _))
      .WillOnce(Return("test-service-owner"))
      .WillOnce(Return("test-service-owner"));
  // Before initialization IsServiceReady fails without checking.
  EXPECT_FALSE(proxy_.IsServiceReady(false /* force_check */));
  EXPECT_FALSE(proxy_.IsServiceReady(true /* force_check */));
  EXPECT_TRUE(proxy_.Init());
  EXPECT_TRUE(proxy_.IsServiceReady(false /* force_check */));
  EXPECT_TRUE(proxy_.IsServiceReady(true /* force_check */));
}

TEST_F(TrunksDBusProxyTest, InitFailure) {
  EXPECT_CALL(*bus_, GetServiceOwnerAndBlock(_, _)).WillRepeatedly(Return(""));
  EXPECT_FALSE(proxy_.Init());
  EXPECT_FALSE(proxy_.IsServiceReady(false /* force_check */));
  EXPECT_FALSE(proxy_.IsServiceReady(true /* force_check */));
}

TEST_F(TrunksDBusProxyTest, InitRetrySuccess) {
  proxy_.set_init_timeout(base::Milliseconds(100));
  EXPECT_CALL(*bus_, GetServiceOwnerAndBlock(_, _))
      .WillOnce(Return(""))
      .WillOnce(Return("test-service-owner"))
      .WillOnce(Return("test-service-owner"));
  EXPECT_TRUE(proxy_.Init());
  EXPECT_TRUE(proxy_.IsServiceReady(false /* force_check */));
  EXPECT_TRUE(proxy_.IsServiceReady(true /* force_check */));
}

TEST_F(TrunksDBusProxyTest, SendCommandSuccess) {
  std::string command = CreateCommand(TPM_CC_FIRST);
  std::string tpm_response = CreateErrorResponse(TPM_RC_SUCCESS);
  TpmErrorData error_data{TPM_CC_FIRST, TPM_RC_SUCCESS};
  EXPECT_CALL(*uma_reporter_, ReportTpm2CommandAndResponse(error_data))
      .WillOnce(Return(true));

  EXPECT_TRUE(proxy_.Init());
  set_next_response(tpm_response);
  auto callback = [](const std::string& response) {
    std::string tpm_response = CreateErrorResponse(TPM_RC_SUCCESS);
    EXPECT_EQ(tpm_response, response);
  };
  proxy_.SendCommand(command, base::BindOnce(callback));
  EXPECT_EQ(command, last_command());
}

TEST_F(TrunksDBusProxyTest, SendCommandAndWaitSuccess) {
  std::string command = CreateCommand(TPM_CC_FIRST);
  std::string tpm_response = CreateErrorResponse(TPM_RC_SUCCESS);
  TpmErrorData error_data{TPM_CC_FIRST, TPM_RC_SUCCESS};
  EXPECT_CALL(*uma_reporter_, ReportTpm2CommandAndResponse(error_data))
      .WillOnce(Return(true));

  EXPECT_TRUE(proxy_.Init());
  set_next_response(tpm_response);
  EXPECT_EQ(tpm_response, proxy_.SendCommandAndWait(command));
  EXPECT_EQ(command, last_command());
}

TEST_F(TrunksDBusProxyTest, SendCommandFailureInit) {
  std::string command = CreateCommand(TPM_CC_FIRST);
  TpmErrorData error_data{TPM_CC_FIRST, SAPI_RC_NO_CONNECTION};
  EXPECT_CALL(*uma_reporter_, ReportTpm2CommandAndResponse(error_data))
      .WillOnce(Return(true));
  // If Init() failed, SAPI_RC_NO_CONNECTION should be returned
  // without sending a command.
  EXPECT_CALL(*bus_, GetServiceOwnerAndBlock(_, _)).WillRepeatedly(Return(""));
  EXPECT_FALSE(proxy_.Init());
  set_next_response("");
  auto callback = [](const std::string& response) {
    EXPECT_EQ(CreateErrorResponse(SAPI_RC_NO_CONNECTION), response);
  };
  proxy_.SendCommand(command, base::BindOnce(callback));
  EXPECT_EQ("", last_command());
}

TEST_F(TrunksDBusProxyTest, SendCommandAndWaitFailureInit) {
  std::string command = CreateCommand(TPM_CC_FIRST);
  std::string trunks_response = CreateErrorResponse(SAPI_RC_NO_CONNECTION);
  TpmErrorData error_data{TPM_CC_FIRST, SAPI_RC_NO_CONNECTION};
  EXPECT_CALL(*uma_reporter_, ReportTpm2CommandAndResponse(error_data))
      .WillOnce(Return(true));
  // If Init() failed, SAPI_RC_NO_CONNECTION should be returned
  // without sending a command.
  EXPECT_CALL(*bus_, GetServiceOwnerAndBlock(_, _)).WillRepeatedly(Return(""));
  EXPECT_FALSE(proxy_.Init());
  set_next_response("");
  EXPECT_EQ(CreateErrorResponse(SAPI_RC_NO_CONNECTION),
            proxy_.SendCommandAndWait(command));
  EXPECT_EQ("", last_command());
}

TEST_F(TrunksDBusProxyTest, SendCommandFailureNoConnection) {
  std::string command = CreateCommand(TPM_CC_FIRST);
  TpmErrorData error_data{TPM_CC_FIRST, SAPI_RC_NO_CONNECTION};
  EXPECT_CALL(*uma_reporter_, ReportTpm2CommandAndResponse(error_data))
      .WillOnce(Return(true));
  // If Init() succeeded, but service is later lost, it should return
  // SAPI_RC_NO_CONNECTION in case there was no response.
  EXPECT_TRUE(proxy_.Init());
  EXPECT_CALL(*bus_, GetServiceOwnerAndBlock(_, _)).WillRepeatedly(Return(""));
  set_next_response("");
  auto callback = [](const std::string& response) {
    EXPECT_EQ(CreateErrorResponse(SAPI_RC_NO_CONNECTION), response);
  };
  proxy_.SendCommand(command, base::BindOnce(callback));
  EXPECT_EQ(command, last_command());
}

TEST_F(TrunksDBusProxyTest, SendCommandAndWaitFailureNoConnection) {
  std::string command = CreateCommand(TPM_CC_FIRST);
  std::string trunks_response = CreateErrorResponse(SAPI_RC_NO_CONNECTION);
  TpmErrorData error_data{TPM_CC_FIRST, SAPI_RC_NO_CONNECTION};
  EXPECT_CALL(*uma_reporter_, ReportTpm2CommandAndResponse(error_data))
      .WillOnce(Return(true));
  // If Init() succeeded, but service is later lost, it should return
  // SAPI_RC_NO_CONNECTION in case there was no response.
  EXPECT_TRUE(proxy_.Init());
  EXPECT_CALL(*bus_, GetServiceOwnerAndBlock(_, _)).WillRepeatedly(Return(""));
  set_next_response("");
  EXPECT_EQ(trunks_response, proxy_.SendCommandAndWait(command));
  EXPECT_EQ(command, last_command());
}

TEST_F(TrunksDBusProxyTest, SendCommandFailureNoResponse) {
  std::string command = CreateCommand(TPM_CC_FIRST);
  TpmErrorData error_data{TPM_CC_FIRST, SAPI_RC_NO_RESPONSE_RECEIVED};
  EXPECT_CALL(*uma_reporter_, ReportTpm2CommandAndResponse(error_data))
      .WillOnce(Return(true));
  // If Init() succeeded and the service is ready, it should return
  // an appropriate error code in case there was no response.
  EXPECT_TRUE(proxy_.Init());
  set_next_response("");
  auto callback = [](const std::string& response) {
    EXPECT_EQ(CreateErrorResponse(SAPI_RC_NO_RESPONSE_RECEIVED), response);
  };
  proxy_.SendCommand(command, base::BindOnce(callback));
  EXPECT_EQ(command, last_command());
}

TEST_F(TrunksDBusProxyTest, SendCommandAndWaitFailureNoResponse) {
  std::string command = CreateCommand(TPM_CC_FIRST);
  std::string trunks_response =
      CreateErrorResponse(SAPI_RC_NO_RESPONSE_RECEIVED);
  TpmErrorData error_data{TPM_CC_FIRST, SAPI_RC_NO_RESPONSE_RECEIVED};
  EXPECT_CALL(*uma_reporter_, ReportTpm2CommandAndResponse(error_data))
      .WillOnce(Return(true));
  // If Init() succeeded and the service is ready, it should return
  // an appropriate error code in case there was no response.
  EXPECT_TRUE(proxy_.Init());
  set_next_response("");
  EXPECT_EQ(trunks_response, proxy_.SendCommandAndWait(command));
  EXPECT_EQ(command, last_command());
}

TEST_F(TrunksDBusProxyTest, SendCommandFailureWrongThread) {
  std::string command = CreateCommand(TPM_CC_FIRST);
  std::string tpm_response = CreateErrorResponse(TPM_RC_SUCCESS);
  TpmErrorData error_data{TPM_CC_FIRST, TRUNKS_RC_IPC_ERROR};
  EXPECT_CALL(*uma_reporter_, ReportTpm2CommandAndResponse(error_data))
      .WillOnce(Return(true));
  // Attempting to send from a wrong thread should return TRUNKS_RC_IPC_ERROR
  // without sending the command.
  EXPECT_TRUE(proxy_.Init());
  // xor 1 would change the thread id without overflow.
  base::PlatformThreadId fake_id = proxy_.origin_thread_id_for_testing() ^ 1;
  proxy_.set_origin_thread_id_for_testing(fake_id);
  set_next_response(tpm_response);
  auto callback = [](const std::string& response) {
    EXPECT_EQ(CreateErrorResponse(TRUNKS_RC_IPC_ERROR), response);
  };
  proxy_.SendCommand(command, base::BindOnce(callback));
  EXPECT_EQ("", last_command());
}

TEST_F(TrunksDBusProxyTest, SendCommandAndWaitFailureWrongThread) {
  std::string command = CreateCommand(TPM_CC_FIRST);
  std::string tpm_response = CreateErrorResponse(TPM_RC_SUCCESS);
  std::string trunks_response = CreateErrorResponse(TRUNKS_RC_IPC_ERROR);
  TpmErrorData error_data{TPM_CC_FIRST, TRUNKS_RC_IPC_ERROR};
  EXPECT_CALL(*uma_reporter_, ReportTpm2CommandAndResponse(error_data))
      .WillOnce(Return(true));
  // Attempting to send from a wrong thread should return TRUNKS_RC_IPC_ERROR
  // without sending the command.
  EXPECT_TRUE(proxy_.Init());
  // xor 1 would change the thread id without overflow.
  base::PlatformThreadId fake_id = proxy_.origin_thread_id_for_testing() ^ 1;
  proxy_.set_origin_thread_id_for_testing(fake_id);
  set_next_response(tpm_response);
  EXPECT_EQ(trunks_response, proxy_.SendCommandAndWait(command));
  EXPECT_EQ("", last_command());
}

TEST_F(TrunksDBusProxyTest, SendCommandNotGeneric) {
  std::string command = CreateCommand(TPM_CC_LAST + 1);
  std::string tpm_response = CreateErrorResponse(TPM_RC_SUCCESS);

  EXPECT_TRUE(proxy_.Init());
  set_next_response(tpm_response);
  auto callback = [](const std::string& response) {
    std::string tpm_response = CreateErrorResponse(TPM_RC_SUCCESS);
    EXPECT_EQ(tpm_response, response);
  };
  proxy_.SendCommand(command, base::BindOnce(callback));
  EXPECT_EQ(command, last_command());
}

TEST_F(TrunksDBusProxyTest, SendCommandAndWaitNotGeneric) {
  std::string command = CreateCommand(TPM_CC_LAST + 1);
  std::string tpm_response = CreateErrorResponse(TPM_RC_SUCCESS);

  EXPECT_TRUE(proxy_.Init());
  set_next_response(tpm_response);
  EXPECT_EQ(tpm_response, proxy_.SendCommandAndWait(command));
  EXPECT_EQ(command, last_command());
}

}  // namespace trunks
