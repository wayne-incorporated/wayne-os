// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/commands/virtualizer.h"

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

#include <base/functional/bind.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <trunks/mock_command_parser.h>
#include <trunks/mock_response_serializer.h>
#include <trunks/tpm_generated.h>

#include "vtpm/commands/mock_command.h"

namespace vtpm {

namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Pointee;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;
using ::testing::WithArgs;

constexpr char kFakeRequest[] = "fake request";
constexpr char kTestResponse[] = "test response";
constexpr trunks::TPM_CC kTestCommandCode = trunks::TPM_CC_Sign;
constexpr trunks::TPM_CC kTestUnsupportedCommandCode =
    trunks::TPM_CC_PCR_Allocate;

}  // namespace

class VirtualizerTest : public testing::Test {
  void SetUp() override {
    std::unordered_map<trunks::TPM_CC, Command*> table;
    table[kTestCommandCode] = &mock_command_;
    virtualizer_ =
        std::make_unique<Virtualizer>(&mock_cmd_parser_, &mock_resp_serializer_,
                                      table, &mock_fallback_command_);
  }

 protected:
  StrictMock<trunks::MockCommandParser> mock_cmd_parser_;
  StrictMock<trunks::MockResponseSerializer> mock_resp_serializer_;
  StrictMock<MockCommand> mock_command_;
  StrictMock<MockCommand> mock_fallback_command_;
  std::unique_ptr<Virtualizer> virtualizer_;
};

namespace {

TEST_F(VirtualizerTest, Delegate) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(mock_cmd_parser_,
              ParseHeader(Pointee(std::string(kFakeRequest)), _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kTestCommandCode),
                      Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_command_, Run(kFakeRequest, _))
      .WillOnce(WithArgs<1>([](CommandResponseCallback callback) {
        std::move(callback).Run(kTestResponse);
      }));
  virtualizer_->Run(kFakeRequest, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(VirtualizerTest, ParserError) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  const trunks::TPM_RC parser_rc = trunks::TPM_RC_INSUFFICIENT;
  EXPECT_CALL(mock_cmd_parser_,
              ParseHeader(Pointee(std::string(kFakeRequest)), _, _, _))
      .WillOnce(Return(parser_rc));
  EXPECT_CALL(mock_resp_serializer_, SerializeHeaderOnlyResponse(parser_rc, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));
  virtualizer_->Run(kFakeRequest, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(VirtualizerTest, Fallback) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(mock_cmd_parser_,
              ParseHeader(Pointee(std::string(kFakeRequest)), _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kTestUnsupportedCommandCode),
                      Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_fallback_command_, Run(kFakeRequest, _))
      .WillOnce(WithArgs<1>([](CommandResponseCallback callback) {
        std::move(callback).Run(kTestResponse);
      }));
  virtualizer_->Run(kFakeRequest, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

}  // namespace

}  // namespace vtpm
