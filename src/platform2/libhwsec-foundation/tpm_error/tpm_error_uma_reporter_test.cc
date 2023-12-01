// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/tpm_error/tpm_error_uma_reporter_impl.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

#include "libhwsec-foundation/tpm_error/tpm_error_constants.h"
#include "libhwsec-foundation/tpm_error/tpm_error_metrics_constants.h"

namespace hwsec_foundation {

namespace {
constexpr uint32_t kFakeCommand = 123;
}

using ::testing::StrictMock;

class TpmErrorUmaReporterTest : public ::testing::Test {
 public:
  TpmErrorUmaReporterTest() = default;
  ~TpmErrorUmaReporterTest() override = default;

 protected:
  StrictMock<MetricsLibraryMock> mock_metrics_library_;
  TpmErrorUmaReporterImpl reporter_{&mock_metrics_library_};
};

TEST_F(TpmErrorUmaReporterTest, ReportTpm1AuthFail) {
  TpmErrorData data;
  data.command = kFakeCommand;
  data.response = kTpm1AuthFailResponse;
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kTpm1AuthFailName, data.command));
  reporter_.Report(data);
}

TEST_F(TpmErrorUmaReporterTest, ReportTpm1Auth2Fail) {
  TpmErrorData data;
  data.command = kFakeCommand;
  data.response = kTpm1Auth2FailResponse;
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kTpm1Auth2FailName, data.command));
  reporter_.Report(data);
}

TEST_F(TpmErrorUmaReporterTest, ReportNoFailure) {
  TpmErrorData data;
  data.command = kFakeCommand;
  data.response = 777;
  ASSERT_NE(data.response, kTpm1AuthFailResponse);
  ASSERT_NE(data.response, kTpm1Auth2FailResponse);
  // Expect no metrics is reported; strict mock will verify.
  reporter_.Report(data);
}

TEST_F(TpmErrorUmaReporterTest, ReportTpm1CommandAndResponse) {
  TpmErrorData data;
  SetTpmMetricsClientID(TpmMetricsClientID::kCryptohome);

  data.command = kFakeCommand;
  data.response = 0;
  std::string metrics_name =
      std::string(kTpm1CommandAndResponsePrefix) + ".Cryptohome";
  uint32_t metrics_value = (data.command << 16) + (data.response & 0xFFFF);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(metrics_name, metrics_value));
  EXPECT_EQ(reporter_.ReportTpm1CommandAndResponse(data), true);
}

TEST_F(TpmErrorUmaReporterTest, ReportTpm1CommandAndResponseUnknownClient) {
  TpmErrorData data;
  SetTpmMetricsClientID(TpmMetricsClientID::kUnknown);

  data.command = kFakeCommand;
  data.response = 0;
  std::string metrics_name =
      std::string(kTpm1CommandAndResponsePrefix) + ".Unknown";
  uint32_t metrics_value = (data.command << 16) + (data.response & 0xFFFF);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(metrics_name, metrics_value));
  EXPECT_EQ(reporter_.ReportTpm1CommandAndResponse(data), true);
}

TEST_F(TpmErrorUmaReporterTest, ReportTpm1CommandAndResponseInvalidValue) {
  TpmErrorData data;
  SetTpmMetricsClientID(TpmMetricsClientID::kCryptohome);
  // Invalid command should not be reported.
  data.command = 0x1000;
  data.response = 0;
  EXPECT_EQ(reporter_.ReportTpm1CommandAndResponse(data), false);
  // Invalid response should not be reported.
  data.command = 0;
  data.response = 0x10000;
  EXPECT_EQ(reporter_.ReportTpm1CommandAndResponse(data), false);
}

TEST_F(TpmErrorUmaReporterTest, ReportTpm2CommandAndResponse) {
  TpmErrorData data;
  SetTpmMetricsClientID(TpmMetricsClientID::kCryptohome);

  data.command = kFakeCommand;
  data.response = 0;
  std::string metrics_name =
      std::string(kTpm2CommandAndResponsePrefix) + ".Cryptohome";
  uint32_t metrics_value = (data.command << 16) + (data.response & 0xFFFF);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(metrics_name, metrics_value));
  EXPECT_EQ(reporter_.ReportTpm2CommandAndResponse(data), true);
}

TEST_F(TpmErrorUmaReporterTest, ReportTpm2CommandAndResponseUnknownClient) {
  TpmErrorData data;
  SetTpmMetricsClientID(TpmMetricsClientID::kUnknown);

  data.command = kFakeCommand;
  data.response = 0;
  std::string metrics_name =
      std::string(kTpm2CommandAndResponsePrefix) + ".Unknown";
  uint32_t metrics_value = (data.command << 16) + (data.response & 0xFFFF);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(metrics_name, metrics_value));
  EXPECT_EQ(reporter_.ReportTpm2CommandAndResponse(data), true);
}

TEST_F(TpmErrorUmaReporterTest, ReportTpm2CommandAndResponseInvalidValue) {
  TpmErrorData data;
  SetTpmMetricsClientID(TpmMetricsClientID::kCryptohome);
  // Invalid command should not be reported.
  data.command = 0x1000;
  data.response = 0;
  EXPECT_EQ(reporter_.ReportTpm2CommandAndResponse(data), false);
  // Invalid response should not be reported.
  data.command = 0;
  data.response = 0x10000;
  EXPECT_EQ(reporter_.ReportTpm2CommandAndResponse(data), false);
}

}  // namespace hwsec_foundation
