/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <memory>
#include <optional>
#include <sstream>
#include <utility>

#include <google/protobuf/util/message_differencer.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>
#include <runtime_probe/proto_bindings/runtime_probe.pb.h>

#include "hardware_verifier/cli.h"
#include "hardware_verifier/hardware_verifier.pb.h"
#include "hardware_verifier/hw_verification_report_getter.h"
#include "hardware_verifier/mock_hw_verification_report_getter.h"
#include "hardware_verifier/observer.h"
#include "hardware_verifier/test_utils.h"

namespace hardware_verifier {

namespace {

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SetArgPointee;

using ReportGetterErrorCode = HwVerificationReportGetter::ErrorCode;

class CLIForTesting : public CLI {
 public:
  CLIForTesting(std::unique_ptr<HwVerificationReportGetter> vr_getter,
                std::ostream* output_stream)
      : CLI(std::move(vr_getter), output_stream) {}
};

class CLITest : public testing::Test {
 protected:
  void SetUp() override {
    auto mock_vr_getter =
        std::make_unique<NiceMock<MockHwVerificationReportGetter>>();
    auto mock_metrics = std::make_unique<NiceMock<MetricsLibraryMock>>();
    mock_vr_getter_ = mock_vr_getter.get();
    output_stream_.reset(new std::ostringstream());
    mock_metrics_ = mock_metrics.get();

    cli_.reset(
        new CLIForTesting(std::move(mock_vr_getter), output_stream_.get()));
    Observer::GetInstance()->SetMetricsLibrary(std::move(mock_metrics));

    // Set everything works by default.
    HwVerificationReport vr;
    vr.set_is_compliant(true);
    ON_CALL(*mock_vr_getter_, Get(_, _, _))
        .WillByDefault(
            DoAll(SetArgPointee<2>(ReportGetterErrorCode::kErrorCodeNoError),
                  Return(vr)));
  }

  void TearDown() override {
    // We have to clear the MetricsLibraryMock manually, because
    // Observer::GetInstance() object is a singleton, which won't be destroyed
    // across the tests.
    Observer::GetInstance()->SetMetricsLibrary(nullptr);
  }

  MockHwVerificationReportGetter* mock_vr_getter_;
  std::unique_ptr<std::ostringstream> output_stream_;
  MetricsLibraryMock* mock_metrics_;

  // The object to be tested.
  std::unique_ptr<CLIForTesting> cli_;
};

TEST_F(CLITest, TestOutput) {
  HwVerificationReport vr;
  vr.set_is_compliant(true);
  ON_CALL(*mock_vr_getter_, Get(_, _, _))
      .WillByDefault(
          DoAll(SetArgPointee<2>(ReportGetterErrorCode::kErrorCodeNoError),
                Return(vr)));

  EXPECT_EQ(cli_->Run("", "", CLIOutputFormat::kProtoBin, true),
            CLIVerificationResult::kPass);
  HwVerificationReport result;
  EXPECT_TRUE(result.ParseFromString(output_stream_->str()));
  EXPECT_TRUE(google::protobuf::util::MessageDifferencer::Equals(result, vr));

  // For human readable format, only check if there's something printed.
  *output_stream_ = std::ostringstream();
  EXPECT_EQ(cli_->Run("", "", CLIOutputFormat::kText, false),
            CLIVerificationResult::kPass);
  EXPECT_FALSE(output_stream_->str().empty());

  *output_stream_ = std::ostringstream();
  EXPECT_EQ(cli_->Run("", "", CLIOutputFormat::kText, true),
            CLIVerificationResult::kPass);
  EXPECT_FALSE(output_stream_->str().empty());
}

TEST_F(CLITest, TestGetReportFailed) {
  ON_CALL(*mock_vr_getter_, Get(_, _, _))
      .WillByDefault(
          DoAll(SetArgPointee<2>(ReportGetterErrorCode::kErrorCodeProbeFail),
                Return(std::nullopt)));

  EXPECT_EQ(cli_->Run("", "", CLIOutputFormat::kProtoBin, true),
            CLIVerificationResult::kProbeFail);
}

TEST_F(CLITest, TestMissingPayloads) {
  ON_CALL(*mock_vr_getter_, Get(_, _, _))
      .WillByDefault(DoAll(
          SetArgPointee<2>(ReportGetterErrorCode::
                               kErrorCodeMissingDefaultHwVerificationSpecFile),
          Return(std::nullopt)));

  EXPECT_EQ(cli_->Run("", "", CLIOutputFormat::kProtoBin, true),
            CLIVerificationResult::kSkippedVerification);
}

TEST_F(CLITest, TestVerifyReportSample1) {
  const auto& path = GetTestDataPath()
                         .Append("verifier_impl_sample_data")
                         .Append("expect_hw_verification_report_1.prototxt");
  const auto& vr = LoadHwVerificationReport(path);
  ON_CALL(*mock_vr_getter_, Get(_, _, _))
      .WillByDefault(
          DoAll(SetArgPointee<2>(ReportGetterErrorCode::kErrorCodeNoError),
                Return(vr)));

  // This is for recording running time.
  EXPECT_CALL(
      *mock_metrics_,
      SendBoolToUMA("ChromeOS.HardwareVerifier.Report.IsCompliant", true));
  // This is for recording qualification status of each components.
  EXPECT_CALL(*mock_metrics_, SendEnumToUMA(_, _, _)).Times(AtLeast(3));

  EXPECT_EQ(cli_->Run("", "", CLIOutputFormat::kText, false),
            CLIVerificationResult::kPass);
}

TEST_F(CLITest, TestVerifyReportSample2) {
  const auto& path = GetTestDataPath()
                         .Append("verifier_impl_sample_data")
                         .Append("expect_hw_verification_report_2.prototxt");
  const auto& vr = LoadHwVerificationReport(path);
  ON_CALL(*mock_vr_getter_, Get(_, _, _))
      .WillByDefault(
          DoAll(SetArgPointee<2>(ReportGetterErrorCode::kErrorCodeNoError),
                Return(vr)));

  // This is for recording running time.
  EXPECT_CALL(
      *mock_metrics_,
      SendBoolToUMA("ChromeOS.HardwareVerifier.Report.IsCompliant", false));
  // This is for recording qualification status of each components.
  EXPECT_CALL(*mock_metrics_, SendEnumToUMA(_, _, _)).Times(AtLeast(2));

  EXPECT_EQ(cli_->Run("", "", CLIOutputFormat::kText, false),
            CLIVerificationResult::kFail);
}

}  // namespace

}  // namespace hardware_verifier
