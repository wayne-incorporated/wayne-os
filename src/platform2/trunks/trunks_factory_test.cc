// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/check_op.h>
#include <base/functional/bind.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "trunks/mock_command_transceiver.h"
#include "trunks/trunks_factory_impl.h"

using testing::_;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;

namespace trunks {

class TrunksFactoryTest : public testing::Test {
 public:
  TrunksFactoryTest() : factory_(&mock_transceiver_) {}
  void SetUp() override {
    ON_CALL(mock_transceiver_, SendCommand(_, _))
        .WillByDefault(Invoke(this, &TrunksFactoryTest::SendCommand));
    ON_CALL(mock_transceiver_, SendCommandAndWait(_))
        .WillByDefault(Invoke(this, &TrunksFactoryTest::SendCommandAndWait));
  }

 protected:
  static std::string BuildSimpleResponse(TPM_RC rc) {
    constexpr int kResponseHeaderSize = 10;
    std::string response;
    Serialize_TPMI_ST_COMMAND_TAG(TPM_ST_NO_SESSIONS, &response);
    Serialize_UINT32(kResponseHeaderSize, &response);
    Serialize_TPM_RC(rc, &response);
    CHECK_EQ(response.size(), kResponseHeaderSize);
    return response;
  }

  void SendCommand(const std::string& command,
                   CommandTransceiver::ResponseCallback callback) {
    std::move(callback).Run(SendCommandAndWait(command));
  }

  std::string SendCommandAndWait(const std::string& command) {
    last_command_ = command;
    return next_response_;
  }

  std::string last_command_;
  std::string next_response_;
  NiceMock<MockCommandTransceiver> mock_transceiver_;
  TrunksFactoryImpl factory_;
};

TEST_F(TrunksFactoryTest, TpmSendCommand) {
  EXPECT_TRUE(factory_.Initialize());
  for (TPM_RC expected_code : {TPM_RC_SUCCESS, TPM_RC_FAILURE}) {
    next_response_ = BuildSimpleResponse(expected_code);
    auto callback = [](TPM_RC expected_code, TPM_RC response_code) {
      EXPECT_EQ(expected_code, response_code);
    };
    factory_.GetTpm()->Startup(TPM_SU_CLEAR, nullptr,
                               base::BindOnce(callback, expected_code));
    EXPECT_EQ(expected_code,
              factory_.GetTpm()->StartupSync(TPM_SU_CLEAR, nullptr));
  }
}

TEST_F(TrunksFactoryTest, TpmSendCommandRetry) {
  EXPECT_TRUE(factory_.Initialize());
  // Async versions of Tpm commands return responses "as is" without any
  // retry logic.
  next_response_ = BuildSimpleResponse(TPM_RC_RETRY);
  auto callback = [](TPM_RC response_code) {
    EXPECT_EQ(TPM_RC_RETRY, response_code);
  };
  factory_.GetTpm()->Startup(TPM_SU_CLEAR, nullptr, base::BindOnce(callback));
  // Sync versions of Tpm commands that call SendCommandAndWait should
  // retry when TPM_RC_RETRY and similar response codes are received.
  factory_.set_command_retry_delay(base::TimeDelta());
  factory_.set_max_command_retries(2);
  // Retries for (max_command_retries-1) attempts.
  EXPECT_CALL(mock_transceiver_, SendCommandAndWait(_))
      .WillOnce(Return(BuildSimpleResponse(TPM_RC_RETRY)))
      .WillOnce(Return(BuildSimpleResponse(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            factory_.GetTpm()->StartupSync(TPM_SU_CLEAR, nullptr));
  // Retries for max_command_retries attempts.
  testing::Mock::VerifyAndClearExpectations(&mock_transceiver_);
  EXPECT_CALL(mock_transceiver_, SendCommandAndWait(_))
      .WillOnce(Return(BuildSimpleResponse(TPM_RC_RETRY)))
      .WillOnce(Return(BuildSimpleResponse(TPM_RC_RETRY)))
      .WillOnce(Return(BuildSimpleResponse(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            factory_.GetTpm()->StartupSync(TPM_SU_CLEAR, nullptr));
  // Retries for >max_command_retries attempts.
  // Sync versions should give up after max number of retries.
  testing::Mock::VerifyAndClearExpectations(&mock_transceiver_);
  EXPECT_CALL(mock_transceiver_, SendCommandAndWait(_))
      .Times(3)
      .WillRepeatedly(Return(BuildSimpleResponse(TPM_RC_RETRY)));
  EXPECT_EQ(TPM_RC_RETRY,
            factory_.GetTpm()->StartupSync(TPM_SU_CLEAR, nullptr));
}

}  // namespace trunks
