// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/commands/nv_read_command.h"

#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <trunks/authorization_delegate.h>
#include <trunks/mock_command_parser.h>
#include <trunks/mock_response_serializer.h>
#include <trunks/tpm_generated.h>

#include "vtpm/backends/mock_nv_space_manager.h"

namespace vtpm {

namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Pointee;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::SetArgReferee;
using ::testing::StrictMock;

constexpr char kFakeRequest[] = "fake request";
constexpr char kTestResponse[] = "test response";
constexpr trunks::TPMI_RH_NV_INDEX kFakeIndex = 0x69696969;
constexpr char kFakePassword[] = "fake password";
constexpr char kFakeData[] = "fake little cheese cake";
constexpr trunks::UINT32 kFakeDataSize = sizeof(kFakeData) - 1;
constexpr trunks::UINT32 kFakeOffset = 0;

MATCHER_P(IsDataEqualTo, d, "") {
  // Check the size first, in case the size in excessively large uninitialized
  // value.
  if (arg.size != std::string(d).size()) {
    return false;
  }
  return std::string(d) == std::string(arg.buffer, arg.buffer + arg.size);
}

}  // namespace

class NvReadCommandTest : public testing::Test {
 public:
  void SetUp() override {
    ON_CALL(mock_cmd_parser_, ParseCommandNvRead(_, _, _, _, _, _))
        .WillByDefault(
            Invoke(this, &NvReadCommandTest::FakeParseCommandNvRead));
  }

 protected:
  trunks::TPM_RC FakeParseCommandNvRead(std::string* command,
                                        trunks::TPMI_RH_NV_AUTH* auth_handle,
                                        trunks::TPMI_RH_NV_INDEX* nv_index,
                                        trunks::TPMS_AUTH_COMMAND* auth,
                                        trunks::UINT16* size,
                                        trunks::UINT16* offset) {
    if (*command != kFakeRequest) {
      return trunks::TPM_RC_COMMAND_CODE;
    }
    command->clear();
    if (parser_rc_) {
      return parser_rc_;
    }

    *auth_handle = auth_handle_;
    *nv_index = nv_index_;
    memcpy(auth, &auth_, sizeof(auth_));
    *size = size_;
    *offset = offset_;

    return parser_rc_;
  }
  StrictMock<trunks::MockCommandParser> mock_cmd_parser_;
  StrictMock<trunks::MockResponseSerializer> mock_resp_serializer_;
  StrictMock<MockNvSpaceManager> mock_nv_space_manager_;

  // Fake parsed command.
  trunks::TPMI_RH_NV_AUTH auth_handle_ = kFakeIndex;
  trunks::TPMI_RH_NV_INDEX nv_index_ = kFakeIndex;
  trunks::TPMS_AUTH_COMMAND auth_ = {
      .session_handle = trunks::TPM_RS_PW,
      .nonce = trunks::Make_TPM2B_DIGEST(""),
      .session_attributes = trunks::kContinueSession,
      .hmac = trunks::Make_TPM2B_DIGEST(kFakePassword),
  };
  trunks::UINT16 size_ = kFakeDataSize;
  trunks::UINT16 offset_ = kFakeOffset;
  trunks::TPM_RC parser_rc_ = trunks::TPM_RC_SUCCESS;

  NvReadCommand command_{&mock_cmd_parser_, &mock_resp_serializer_,
                         &mock_nv_space_manager_};
};

namespace {

TEST_F(NvReadCommandTest, Success) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(
      mock_cmd_parser_,
      ParseCommandNvRead(Pointee(std::string(kFakeRequest)), _, _, _, _, _));
  EXPECT_CALL(mock_nv_space_manager_, Read(kFakeIndex, kFakePassword, _))
      .WillOnce(
          DoAll(SetArgReferee<2>(kFakeData), Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_resp_serializer_,
              SerializeResponseNvRead(IsDataEqualTo(kFakeData), _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  command_.Run(kFakeRequest, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(NvReadCommandTest, SuccessPartialData) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(
      mock_cmd_parser_,
      ParseCommandNvRead(Pointee(std::string(kFakeRequest)), _, _, _, _, _));
  EXPECT_CALL(mock_nv_space_manager_, Read(kFakeIndex, kFakePassword, _))
      .WillOnce(
          DoAll(SetArgReferee<2>(kFakeData), Return(trunks::TPM_RC_SUCCESS)));

  offset_ = 1;
  size_ -= 1;
  EXPECT_CALL(
      mock_resp_serializer_,
      SerializeResponseNvRead(
          IsDataEqualTo(std::string(kFakeData).substr(offset_, size_)), _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  command_.Run(kFakeRequest, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(NvReadCommandTest, FailureOutOfRange) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(
      mock_cmd_parser_,
      ParseCommandNvRead(Pointee(std::string(kFakeRequest)), _, _, _, _, _));
  EXPECT_CALL(mock_nv_space_manager_, Read(kFakeIndex, kFakePassword, _))
      .WillOnce(
          DoAll(SetArgReferee<2>(kFakeData), Return(trunks::TPM_RC_SUCCESS)));

  offset_ = 1;
  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_NV_RANGE, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  command_.Run(kFakeRequest, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(NvReadCommandTest, FailureNvSapceError) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(
      mock_cmd_parser_,
      ParseCommandNvRead(Pointee(std::string(kFakeRequest)), _, _, _, _, _));
  EXPECT_CALL(mock_nv_space_manager_, Read(kFakeIndex, kFakePassword, _))
      .WillOnce(Return(trunks::TPM_RC_HANDLE));

  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_HANDLE, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  command_.Run(kFakeRequest, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(NvReadCommandTest, FailureInconsistentAuthIndex) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);

  EXPECT_CALL(
      mock_cmd_parser_,
      ParseCommandNvRead(Pointee(std::string(kFakeRequest)), _, _, _, _, _));

  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_NV_AUTHORIZATION, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  ++auth_handle_;

  command_.Run(kFakeRequest, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(NvReadCommandTest, FailureWrongSessionHandle) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(
      mock_cmd_parser_,
      ParseCommandNvRead(Pointee(std::string(kFakeRequest)), _, _, _, _, _));

  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_HANDLE, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  ++auth_.session_handle;

  command_.Run(kFakeRequest, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(NvReadCommandTest, FailureExcessiveLargeSizeToRead) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  size_ = MAX_NV_BUFFER_SIZE + 1;
  EXPECT_CALL(
      mock_cmd_parser_,
      ParseCommandNvRead(Pointee(std::string(kFakeRequest)), _, _, _, _, _));

  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_VALUE, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  command_.Run(kFakeRequest, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(NvReadCommandTest, FailureParserError) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(
      mock_cmd_parser_,
      ParseCommandNvRead(Pointee(std::string(kFakeRequest)), _, _, _, _, _));

  parser_rc_ = trunks::TPM_RC_INSUFFICIENT;

  EXPECT_CALL(mock_resp_serializer_, SerializeHeaderOnlyResponse(parser_rc_, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  ++auth_.session_handle;

  command_.Run(kFakeRequest, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

}  // namespace

}  // namespace vtpm
