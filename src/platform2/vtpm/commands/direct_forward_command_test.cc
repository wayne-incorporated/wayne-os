// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/commands/direct_forward_command.h"

#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <trunks/mock_tpm_utility.h>
#include <trunks/tpm_generated.h>
#include <trunks/trunks_factory_for_test.h>

namespace vtpm {

namespace {

using ::testing::_;
using ::testing::Return;
using ::testing::StrictMock;

constexpr char kFakeRequest[] = "fake request";
constexpr char kTestResponse[] = "test response";

}  // namespace

class DirectForwardCommandTest : public testing::Test {
 public:
  void SetUp() override { factory_.set_tpm_utility(&mock_tpm_utility_); }

 protected:
  StrictMock<trunks::MockTpmUtility> mock_tpm_utility_;
  trunks::TrunksFactoryForTest factory_;
  DirectForwardCommand command_{&factory_};
};

namespace {

TEST_F(DirectForwardCommandTest, CallsCallback) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(mock_tpm_utility_, SendCommandAndWait(_))
      .WillOnce(Return(kTestResponse));
  command_.Run(kFakeRequest, std::move(callback));

  EXPECT_EQ(response, kTestResponse);
}

}  // namespace

}  // namespace vtpm
