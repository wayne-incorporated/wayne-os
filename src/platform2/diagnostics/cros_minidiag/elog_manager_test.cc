// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_minidiag/elog_manager.h"

#include <array>
#include <memory>
#include <optional>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

#include "diagnostics/cros_minidiag/minidiag_metrics.h"

using cros_minidiag::metrics::MiniDiagResultType;

namespace cros_minidiag {

namespace {

const std::array<const char*, 6> kElogLines = {
    "1 | 2022-01-01 00:00:00+0000 | Mock Type | Mock Data",
    "2 | 2022-01-01 00:00:01+0000 | Mock Type | Mock Data",
    "3 | 2022-01-01 00:00:02+0000 | Mock Type | Mock Data",
    "4 | 2022-01-01 00:00:03+0000 | Mock Type | Mock Data",
    "5 | 2022-01-01 00:00:04+0000 | Mock Type | Mock Data",
    "6 | 2022-01-01 00:00:05+0000 | Mock Type | Mock Data",
};

}  // namespace

class ElogManagerTest : public testing::Test {
 protected:
  void SetUp() override {
    minidiag_metrics_.SetMetricsLibraryForTesting(&mock_metrics_library_);
  }
  template <std::size_t N>
  void SetUpElog(const std::array<const char*, N>& raw_logs) {
    full_elog_.clear();
    for (const auto& line : raw_logs) {
      full_elog_.append(line);
      full_elog_.append("\n");
    }
    size_ = N;
  }
  void ExpectUMA(std::string test_name,
                 MiniDiagResultType result,
                 int duration) {
    // Expect the result UMA
    EXPECT_CALL(
        mock_metrics_library_,
        SendEnumToUMA(test_name + metrics::kSuffixResult,
                      static_cast<int>(result),
                      static_cast<int>(metrics::MiniDiagResultType::kMaxValue)))
        .WillOnce(testing::Return(true));
    // Expect the open duration UMA
    EXPECT_CALL(mock_metrics_library_,
                SendToUMA(test_name + metrics::kSuffixOpenDuration, duration,
                          metrics::kOpenDurationMin, metrics::kOpenDurationMax,
                          metrics::kOpenDurationBucket))
        .WillOnce(testing::Return(true));
  }
  void ExpectOpenDurationUMA(int duration) {
    EXPECT_CALL(mock_metrics_library_,
                SendToUMA(metrics::kOpenDurationHistogram, duration,
                          metrics::kOpenDurationMin, metrics::kOpenDurationMax,
                          metrics::kOpenDurationBucket))
        .WillOnce(testing::Return(true));
  }

  std::string full_elog_;
  std::size_t size_;
  testing::StrictMock<MetricsLibraryMock> mock_metrics_library_;
  MiniDiagMetrics minidiag_metrics_;
};

TEST_F(ElogManagerTest, BasicLastLine) {
  SetUpElog(kElogLines);
  auto elog_manager =
      std::make_unique<ElogManager>(full_elog_, "", &minidiag_metrics_);
  EXPECT_EQ(elog_manager->last_line(), kElogLines[size_ - 1]);
  EXPECT_EQ(elog_manager->GetEventNum(), size_);
}

TEST_F(ElogManagerTest, TestPreviousLastLine) {
  const int idx = 3;
  SetUpElog(kElogLines);
  ASSERT_TRUE(idx < size_);
  auto elog_manager = std::make_unique<ElogManager>(full_elog_, kElogLines[idx],
                                                    &minidiag_metrics_);
  EXPECT_EQ(elog_manager->last_line(), kElogLines[size_ - 1]);
  EXPECT_EQ(elog_manager->GetEventNum(), size_ - idx - 1);
}

TEST_F(ElogManagerTest, BadPreviousLastLine) {
  SetUpElog(kElogLines);
  auto elog_manager =
      std::make_unique<ElogManager>(full_elog_, "XXX", &minidiag_metrics_);
  EXPECT_EQ(elog_manager->last_line(), kElogLines[size_ - 1]);
  EXPECT_EQ(elog_manager->GetEventNum(), size_);
}

TEST_F(ElogManagerTest, BasicReportMiniDiagLaunch) {
  SetUpElog(std::array<const char*, 6>({
      "1 | 2022-01-01 00:00:00+0000 | Mock Type",
      // Legacy launch event
      "2 | 2022-01-01 00:00:01+0000 | Diagnostics Mode | Launch Diagnostics",
      "3 | 2022-01-01 00:00:02+0000 | Mock Type | Mock Data",
      "4 | 2022-01-01 00:00:03+0000 | Mock Type | Mock Data",
      // New launch event
      "5 | 2022-01-01 00:00:04+0000 | Firmware vboot info | "
      "boot_mode=Diagnostic | fw_tried=A | fw_try_count=0 | fw_prev_tried=A | "
      "fw_prev_result=Unknown",
      "6 | 2022-01-01 00:00:05+0000 | Mock Type | Mock Data",
  }));
  EXPECT_CALL(
      mock_metrics_library_,
      SendLinearToUMA(metrics::kLaunchHistogram, 2, metrics::kLaunchCountMax))
      .WillOnce(testing::Return(true));
  auto elog_manager =
      std::make_unique<ElogManager>(full_elog_, "", &minidiag_metrics_);
  EXPECT_EQ(elog_manager->last_line(), kElogLines[size_ - 1]);
  EXPECT_EQ(elog_manager->GetEventNum(), size_);
  elog_manager->ReportMiniDiagLaunch();
}

TEST_F(ElogManagerTest, BasicTestReport) {
  SetUpElog(std::array<const char*, 4>({
      "1 | 2022-01-01 00:00:01+0000 | Diagnostics Mode | Launch Diagnostics",
      "2 | 2022-01-01 00:01:01+0000 | Diagnostics Mode | Diagnostics Logs | "
      "type=Memory check (quick), result=Passed, time=0m20s | "
      "type=Memory check (full), result=Aborted, time=0m0s | "
      "type=Memory check (quick), result=Aborted, time=0m0s | "
      "type=Storage health info, result=Passed, time=0m0s",
      "3 | 2022-01-01 01:01:01+0000 | Diagnostics Mode | Diagnostics Logs | "
      "type=Storage self-test (short), result=Error, time=10m20s | "
      "type=Storage self-test (extended), result=Failed, time=1m1s | "
      "type=Storage self-test (extended), result=Passed, time=2m0s",
      // Bad event; ignored
      "4 | 2022-01-01 02:01:01+0000 | Diagnostics Mode | Diagnostics Logs | "
      "type=Mock ",
  }));
  ExpectUMA(metrics::kMemoryCheckQuick, MiniDiagResultType::kPassed, 20);
  ExpectUMA(metrics::kMemoryCheckFull, MiniDiagResultType::kAborted, 0);
  ExpectUMA(metrics::kMemoryCheckQuick, MiniDiagResultType::kAborted, 0);
  ExpectUMA(metrics::kStorageHealthInfo, MiniDiagResultType::kPassed, 0);
  ExpectOpenDurationUMA(20);
  ExpectUMA(metrics::kStorageSelfTestShort, MiniDiagResultType::kError, 620);
  ExpectUMA(metrics::kStorageSelfTestExtended, MiniDiagResultType::kFailed, 61);
  ExpectUMA(metrics::kStorageSelfTestExtended, MiniDiagResultType::kPassed,
            120);
  ExpectOpenDurationUMA(801);
  auto elog_manager =
      std::make_unique<ElogManager>(full_elog_, "", &minidiag_metrics_);
  elog_manager->ReportMiniDiagTestReport();
}

TEST_F(ElogManagerTest, TestReportCaseInsensitive) {
  SetUpElog(std::array<const char*, 1>(
      {"2 | 2022-01-01 00:01:01+0000 | Diagnostics Mode | Diagnostics Logs | "
       "type=mEmorY CHECK (quicK), result=paSSEd, time=0m20s "}));
  ExpectUMA(metrics::kMemoryCheckQuick, MiniDiagResultType::kPassed, 20);
  ExpectOpenDurationUMA(20);
  auto elog_manager =
      std::make_unique<ElogManager>(full_elog_, "", &minidiag_metrics_);
  elog_manager->ReportMiniDiagTestReport();
}

TEST(ElogEventTest, BasicEvent) {
  auto event =
      std::make_unique<ElogEvent>("1 | 2022-01-01 00:00:00+0000 | Mock Type");
  auto type = event->GetType();
  auto subtype = event->GetSubType();
  EXPECT_TRUE(!!type);
  EXPECT_EQ(*type, "Mock Type");
  EXPECT_FALSE(!!subtype);
}

TEST(ElogEventTest, BasicEventWithSubtype) {
  auto event = std::make_unique<ElogEvent>(
      "1 | 2022-01-01 00:00:00+0000 | Mock Type | Mock SubType | "
      "Additional Data");
  auto type = event->GetType();
  auto subtype = event->GetSubType();
  EXPECT_TRUE(!!type);
  EXPECT_EQ(*type, "Mock Type");
  EXPECT_TRUE(!!subtype);
  EXPECT_EQ(*subtype, "Mock SubType");
}

TEST(ElogEventTest, BadEventEmpty) {
  auto event = std::make_unique<ElogEvent>("");
  auto type = event->GetType();
  auto subtype = event->GetSubType();
  EXPECT_FALSE(!!type);
  EXPECT_FALSE(!!subtype);
}

TEST(ElogEventTest, BadEventColumnTooFew) {
  auto event = std::make_unique<ElogEvent>("6 | 2022-01-01");
  auto type = event->GetType();
  auto subtype = event->GetSubType();
  EXPECT_FALSE(!!type);
  EXPECT_FALSE(!!subtype);
}

}  // namespace cros_minidiag
