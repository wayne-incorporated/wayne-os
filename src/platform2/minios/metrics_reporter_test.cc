// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "metrics/metrics_library_mock.h"
#include "minios/metrics_reporter.h"
#include "minios/mock_process_manager.h"

using ::testing::_;
using ::testing::StrictMock;

namespace minios {

class MetricsReporterTest : public ::testing::Test {
 protected:
  std::unique_ptr<MockProcessManager> mock_process_manager_ =
      std::make_unique<StrictMock<MockProcessManager>>();
  MockProcessManager* mock_process_manager_ptr_ = mock_process_manager_.get();

  std::unique_ptr<MetricsLibraryMock> metrics_library_mock_ =
      std::make_unique<StrictMock<MetricsLibraryMock>>();
  MetricsLibraryMock* metrics_library_mock_ptr_ = metrics_library_mock_.get();

  std::unique_ptr<MetricsReporter> reporter_;

  void SetUp() override {
    EXPECT_CALL(*metrics_library_mock_ptr_, Init);
    reporter_ = std::make_unique<MetricsReporter>(
        mock_process_manager_ptr_, std::move(metrics_library_mock_));
  }
};

TEST_F(MetricsReporterTest, ReportNBRComplete) {
  EXPECT_CALL(*mock_process_manager_ptr_, RunCommand)
      .WillOnce(::testing::Return(0));
  EXPECT_CALL(*metrics_library_mock_ptr_, SetOutputFile(kStatefulEventsPath));
  EXPECT_CALL(*metrics_library_mock_ptr_,
              SendEnumToUMA(kRecoveryReason, kRecoveryReasonCode_NBR,
                            kRecoveryReasonCode_MAX));
  EXPECT_CALL(*metrics_library_mock_ptr_,
              SendToUMA(kRecoveryDurationMinutes, _, /*min=*/0,
                        kRecoveryDurationMinutes_MAX,
                        kRecoveryDurationMinutes_Buckets));
  reporter_->ReportNBRComplete();
}

TEST_F(MetricsReporterTest, ReportNBRCompleteFailToMountStateful) {
  EXPECT_CALL(*mock_process_manager_ptr_, RunCommand)
      .WillOnce(::testing::Return(1));
  reporter_->ReportNBRComplete();
}

}  // namespace minios
