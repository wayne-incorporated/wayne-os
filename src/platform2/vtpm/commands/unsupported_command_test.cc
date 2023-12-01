// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/commands/unsupported_command.h"

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

constexpr char kFakeRequest[] = "fake request";
constexpr char kTestResponse[] = "test response";

}  // namespace

// A placeholder test fixture.
class UnsupportedCommandTest : public testing::Test {
 protected:
  StrictMock<trunks::MockResponseSerializer> mock_resp_serializer_;
  UnsupportedCommand command_{&mock_resp_serializer_};
};

namespace {

TEST_F(UnsupportedCommandTest, CallsCallback) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_COMMAND_CODE, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  command_.Run(kFakeRequest, std::move(callback));

  EXPECT_EQ(response, kTestResponse);
}

}  // namespace

}  // namespace vtpm
