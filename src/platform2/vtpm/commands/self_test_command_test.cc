// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/commands/self_test_command.h"

#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <trunks/mock_response_serializer.h>
#include <trunks/tpm_generated.h>

namespace vtpm {

namespace {

using ::testing::_;
using ::testing::SetArgPointee;
using ::testing::StrictMock;

constexpr char kTestResponse[] = "test response";

}  // namespace

// A placeholder test fixture.
class SelfTestCommandTest : public testing::Test {
 protected:
  StrictMock<trunks::MockResponseSerializer> mock_resp_serializer_;
  SelfTestCommand command_{&mock_resp_serializer_};
};

namespace {

TEST_F(SelfTestCommandTest, Success) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_SUCCESS, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  std::string command;
  trunks::Tpm::SerializeCommand_SelfTest(YES, &command,
                                         /*authorization_delegate=*/nullptr);
  command_.Run(command, std::move(callback));

  EXPECT_EQ(response, kTestResponse);
}

TEST_F(SelfTestCommandTest, FailureUnexpectedCommandCode) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_COMMAND_CODE, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  std::string command;
  trunks::Tpm::SerializeCommand_SelfTest(YES, &command,
                                         /*authorization_delegate=*/nullptr);

  // Change the command code. The range of the command code in `command` is
  // [6:10).
  command[9] += 1;

  command_.Run(command, std::move(callback));

  EXPECT_EQ(response, kTestResponse);
}

TEST_F(SelfTestCommandTest, FailureBadHeader) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_INSUFFICIENT, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  std::string command;
  trunks::Tpm::SerializeCommand_SelfTest(YES, &command,
                                         /*authorization_delegate=*/nullptr);

  // Make a bad header.
  command.resize(5);

  command_.Run(command, std::move(callback));

  EXPECT_EQ(response, kTestResponse);
}

TEST_F(SelfTestCommandTest, FailureCommandTooLong) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_SIZE, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  std::string command;
  trunks::Tpm::SerializeCommand_SelfTest(YES, &command,
                                         /*authorization_delegate=*/nullptr);

  // Add excessive data.
  command += "data at tail";

  command_.Run(command, std::move(callback));

  EXPECT_EQ(response, kTestResponse);
}

}  // namespace

}  // namespace vtpm
