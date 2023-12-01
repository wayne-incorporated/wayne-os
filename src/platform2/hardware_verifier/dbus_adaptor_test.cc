/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hardware_verifier/dbus_adaptor.h"

#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <brillo/dbus/mock_dbus_method_response.h>
#include <google/protobuf/util/message_differencer.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "hardware_verifier/hardware_verifier.pb.h"
#include "hardware_verifier/hw_verification_report_getter.h"
#include "hardware_verifier/mock_hw_verification_report_getter.h"

namespace hardware_verifier {

namespace {

using ::brillo::dbus_utils::MockDBusMethodResponse;

using ::testing::_;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SetArgPointee;

using ReportGetterErrorCode = HwVerificationReportGetter::ErrorCode;

class DBusAdaptorForTesting : public DBusAdaptor {
 public:
  explicit DBusAdaptorForTesting(
      std::unique_ptr<HwVerificationReportGetter> vr_getter)
      : DBusAdaptor(std::move(vr_getter)) {}
};

class DBusAdaptorTest : public testing::Test {
 protected:
  void SetUp() override {
    auto mock_vr_getter =
        std::make_unique<NiceMock<MockHwVerificationReportGetter>>();
    vr_getter_ = mock_vr_getter.get();
    adaptor_.reset(new DBusAdaptorForTesting(std::move(mock_vr_getter)));
  }

  void TearDown() override {}

  // Mocks that will be passed into |adaptor_| for its internal use.
  MockHwVerificationReportGetter* vr_getter_;

  // The adaptor that we'll be testing.
  std::unique_ptr<DBusAdaptor> adaptor_;
};

TEST_F(DBusAdaptorTest, VerifyComponents_Success) {
  HwVerificationReport vr;
  vr.set_is_compliant(true);
  ON_CALL(*vr_getter_, Get(_, _, _))
      .WillByDefault(
          DoAll(SetArgPointee<2>(ReportGetterErrorCode ::kErrorCodeNoError),
                Return(vr)));
  std::optional<VerifyComponentsReply> reply;
  auto response =
      std::make_unique<MockDBusMethodResponse<VerifyComponentsReply>>(nullptr);
  response->save_return_args(&reply);
  adaptor_->VerifyComponents(std::move(response));

  EXPECT_TRUE(reply);
  EXPECT_EQ(reply->error(), ERROR_OK);
  EXPECT_TRUE(google::protobuf::util::MessageDifferencer::Equals(
      reply->hw_verification_report(), vr));
}

TEST_F(DBusAdaptorTest, VerifyComponents_Fail) {
  std::vector<std::pair<ReportGetterErrorCode, ErrorCode>> testdata = {
      {ReportGetterErrorCode::kErrorCodeMissingDefaultHwVerificationSpecFile,
       ERROR_SKIPPED},
      {ReportGetterErrorCode::kErrorCodeInvalidHwVerificationSpecFile,
       ERROR_INVALID_HW_VERIFICATION_SPEC_FILE},
      {ReportGetterErrorCode::kErrorCodeInvalidProbeResultFile,
       ERROR_INVALID_PROBE_RESULT_FILE},
      {ReportGetterErrorCode::kErrorCodeProbeFail, ERROR_PROBE_FAIL},
      {ReportGetterErrorCode::
           kErrorCodeProbeResultHwVerificationSpecMisalignment,
       ERROR_PROBE_RESULT_HW_VERIFICATION_SPEC_MISALIGNMENT}};
  for (const auto& [input, output] : testdata) {
    ON_CALL(*vr_getter_, Get(_, _, _))
        .WillByDefault(DoAll(SetArgPointee<2>(input), Return(std::nullopt)));
    std::optional<VerifyComponentsReply> reply;
    auto response =
        std::make_unique<MockDBusMethodResponse<VerifyComponentsReply>>(
            nullptr);
    response->save_return_args(&reply);
    adaptor_->VerifyComponents(std::move(response));

    EXPECT_TRUE(reply);
    EXPECT_EQ(reply->error(), output);
  }
}

}  // namespace

}  // namespace hardware_verifier
