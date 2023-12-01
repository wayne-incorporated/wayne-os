// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/types/cxx23_to_underlying.h>
#include <chromeos/ec/ec_commands.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

#include "biod/biod_metrics.h"
#include "biod/updater/update_reason.h"
#include "biod/utils.h"

using ::testing::_;
using ::testing::Ge;
using ::testing::Le;

namespace biod {
namespace {

class BiodMetricsTest : public testing::Test {
 protected:
  BiodMetricsTest() {
    biod_metrics_.SetMetricsLibraryForTesting(
        std::make_unique<MetricsLibraryMock>());
  }
  BiodMetricsTest(const BiodMetricsTest&) = delete;
  BiodMetricsTest& operator=(const BiodMetricsTest&) = delete;

  ~BiodMetricsTest() override = default;

  MetricsLibraryMock* GetMetricsLibraryMock() {
    return static_cast<MetricsLibraryMock*>(
        biod_metrics_.metrics_library_for_testing());
  }

  BiodMetrics biod_metrics_;
};

TEST_F(BiodMetricsTest, SendEnrolledFingerCount) {
  const int finger_count = 2;
  EXPECT_CALL(*GetMetricsLibraryMock(), SendEnumToUMA(_, finger_count, _))
      .Times(1);
  biod_metrics_.SendEnrolledFingerCount(finger_count);
}

TEST_F(BiodMetricsTest, SendEnrollmentCapturesCount) {
  const int captures_count = 2;
  EXPECT_CALL(*GetMetricsLibraryMock(), SendEnumToUMA(_, captures_count, _))
      .Times(1);
  biod_metrics_.SendEnrolledFingerCount(captures_count);
}

TEST_F(BiodMetricsTest, SendFpUnlockEnabled) {
  EXPECT_CALL(*GetMetricsLibraryMock(), SendBoolToUMA(_, true)).Times(1);
  EXPECT_CALL(*GetMetricsLibraryMock(), SendBoolToUMA(_, false)).Times(1);
  biod_metrics_.SendFpUnlockEnabled(true);
  biod_metrics_.SendFpUnlockEnabled(false);
}

TEST_F(BiodMetricsTest, SendFpLatencyStatsOnMatch) {
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kFpMatchDurationCapture, _, _, _, _))
      .Times(1);
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kFpMatchDurationMatcher, _, _, _, _))
      .Times(1);
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kFpMatchDurationOverall, _, _, _, _))
      .Times(1);
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kFpNoMatchDurationCapture, _, _, _, _))
      .Times(0);
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kFpNoMatchDurationMatcher, _, _, _, _))
      .Times(0);
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kFpNoMatchDurationOverall, _, _, _, _))
      .Times(0);
  biod_metrics_.SendFpLatencyStats(
      true, {.capture_ms = 0, .matcher_ms = 0, .overall_ms = 0});
}

TEST_F(BiodMetricsTest, SendFpLatencyStatsOnNoMatch) {
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kFpMatchDurationCapture, _, _, _, _))
      .Times(0);
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kFpMatchDurationMatcher, _, _, _, _))
      .Times(0);
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kFpMatchDurationOverall, _, _, _, _))
      .Times(0);
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kFpNoMatchDurationCapture, _, _, _, _))
      .Times(1);
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kFpNoMatchDurationMatcher, _, _, _, _))
      .Times(1);
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kFpNoMatchDurationOverall, _, _, _, _))
      .Times(1);
  biod_metrics_.SendFpLatencyStats(
      false, {.capture_ms = 0, .matcher_ms = 0, .overall_ms = 0});
}

TEST_F(BiodMetricsTest, SendFpLatencyStatsValues) {
  constexpr ec::CrosFpDeviceInterface::FpStats stats = {
      .capture_ms = 70,
      .matcher_ms = 187,
      .overall_ms = 223,
  };
  EXPECT_CALL(*GetMetricsLibraryMock(), SendToUMA(_, stats.capture_ms, _, _, _))
      .Times(2);
  EXPECT_CALL(*GetMetricsLibraryMock(), SendToUMA(_, stats.matcher_ms, _, _, _))
      .Times(2);
  EXPECT_CALL(*GetMetricsLibraryMock(), SendToUMA(_, stats.overall_ms, _, _, _))
      .Times(2);
  biod_metrics_.SendFpLatencyStats(true, stats);
  biod_metrics_.SendFpLatencyStats(false, stats);
}

TEST_F(BiodMetricsTest, SendFwUpdaterStatusOnNoUpdate) {
  const auto status = BiodMetrics::FwUpdaterStatus::kUnnecessary;
  const auto reason = updater::UpdateReason::kNone;
  const int overall_ms = 60;

  // TODO(b/266077024) Change UMA enum names for kUpdaterStatus if new
  // enums are added to avoid data discontinuity, and then use kMaxValue+1
  // rather than kMaxValue for 'exclusive_max'.
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendEnumToUMA(
                  metrics::kUpdaterStatus, base::to_underlying(status),
                  base::to_underlying(BiodMetrics::FwUpdaterStatus::kMaxValue)))
      .Times(1);

  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kUpdaterDurationNoUpdate, overall_ms,
                        Le(overall_ms), Ge(overall_ms), _))
      .Times(1);

  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kUpdaterDurationUpdate, _, _, _, _))
      .Times(0);

  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(metrics::kUpdaterReason, base::to_underlying(reason),
                    base::to_underlying(updater::UpdateReason::kMaxValue) + 1))
      .Times(1);
  biod_metrics_.SendFwUpdaterStatus(status, reason, overall_ms);
}

TEST_F(BiodMetricsTest, SendFwUpdaterStatusOnUpdate) {
  const auto status = BiodMetrics::FwUpdaterStatus::kFailureUpdateRW;
  const auto reason = updater::UpdateReason::kMismatchRWVersion |
                      updater::UpdateReason::kMismatchROVersion;
  const int overall_ms = 40 * 1000;

  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendEnumToUMA(
                  metrics::kUpdaterStatus, base::to_underlying(status),
                  base::to_underlying(BiodMetrics::FwUpdaterStatus::kMaxValue)))
      .Times(1);

  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kUpdaterDurationNoUpdate, _, _, _, _))
      .Times(0);

  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kUpdaterDurationUpdate, overall_ms,
                        Le(overall_ms), Ge(overall_ms), _))
      .Times(1);

  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(metrics::kUpdaterReason, base::to_underlying(reason),
                    base::to_underlying(updater::UpdateReason::kMaxValue) + 1))
      .Times(1);
  biod_metrics_.SendFwUpdaterStatus(status, reason, overall_ms);
}

TEST_F(BiodMetricsTest, SendIgnoreMatchEventOnPowerButtonPress) {
  EXPECT_CALL(*GetMetricsLibraryMock(), SendBoolToUMA(_, true)).Times(1);
  biod_metrics_.SendIgnoreMatchEventOnPowerButtonPress(true);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());
  EXPECT_CALL(*GetMetricsLibraryMock(), SendBoolToUMA(_, false)).Times(1);
  biod_metrics_.SendIgnoreMatchEventOnPowerButtonPress(false);
}

TEST_F(BiodMetricsTest, SendReadPositiveMatchSecretSuccess) {
  EXPECT_CALL(*GetMetricsLibraryMock(), SendBoolToUMA(_, true)).Times(1);
  biod_metrics_.SendReadPositiveMatchSecretSuccess(true);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());
  EXPECT_CALL(*GetMetricsLibraryMock(), SendBoolToUMA(_, false)).Times(1);
  biod_metrics_.SendReadPositiveMatchSecretSuccess(false);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());
}

TEST_F(BiodMetricsTest, SendPositiveMatchSecretCorrect) {
  EXPECT_CALL(*GetMetricsLibraryMock(), SendBoolToUMA(_, true)).Times(1);
  biod_metrics_.SendPositiveMatchSecretCorrect(true);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());
  EXPECT_CALL(*GetMetricsLibraryMock(), SendBoolToUMA(_, false)).Times(1);
  biod_metrics_.SendPositiveMatchSecretCorrect(false);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());
}

TEST_F(BiodMetricsTest, SendResetContextMode) {
  constexpr int kExpectedResetSensorEnum = 10;
  constexpr int kExpectedMaxEnum = 18;

  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendEnumToUMA(metrics::kResetContextMode,
                            kExpectedResetSensorEnum, kExpectedMaxEnum))
      .Times(1);
  biod_metrics_.SendResetContextMode(
      ec::FpMode(ec::FpMode::Mode::kResetSensor));
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());
}

TEST_F(BiodMetricsTest, SendDeadPixelCount) {
  constexpr int kExpectedNumDead = 5;
  constexpr int kExpectedMin = 0;
  constexpr int kExpectedMax = 1022;
  constexpr int kExpectedNumBuckets = 50;

  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kNumDeadPixels, kExpectedNumDead, kExpectedMin,
                        kExpectedMax, kExpectedNumBuckets))
      .Times(1);
  biod_metrics_.SendDeadPixelCount(5);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());
}

TEST_F(BiodMetricsTest, SendUploadTemplateResult) {
  constexpr int kExpectedSuccessEnum = 0;
  constexpr int kExpectedInvalidParamEnum = 3;
  constexpr int kExpectedUnavailableEnum = 9;
  constexpr int kExpectedMinEnum = -1;
  constexpr int kExpectedMaxEnum = 20;
  constexpr int kExpectedNumBuckets = 22;

  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(_, kExpectedSuccessEnum, kExpectedMinEnum,
                        kExpectedMaxEnum, kExpectedNumBuckets))
      .Times(1);
  biod_metrics_.SendUploadTemplateResult(EC_RES_SUCCESS);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(_, kExpectedInvalidParamEnum, kExpectedMinEnum,
                        kExpectedMaxEnum, kExpectedNumBuckets))
      .Times(1);
  biod_metrics_.SendUploadTemplateResult(EC_RES_INVALID_PARAM);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(_, kExpectedUnavailableEnum, kExpectedMinEnum,
                        kExpectedMaxEnum, kExpectedNumBuckets))
      .Times(1);
  biod_metrics_.SendUploadTemplateResult(EC_RES_UNAVAILABLE);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());
}

TEST_F(BiodMetricsTest, SendPartialAttemptsBeforeSuccess) {
  const int partial_attempts = 2;
  EXPECT_CALL(*GetMetricsLibraryMock(), SendEnumToUMA(_, partial_attempts, _))
      .Times(1);
  biod_metrics_.SendPartialAttemptsBeforeSuccess(partial_attempts);
}

TEST_F(BiodMetricsTest, SendFpSensorErrorNoIrq) {
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendBoolToUMA(metrics::kFpSensorErrorNoIrq, true))
      .Times(1);
  biod_metrics_.SendFpSensorErrorNoIrq(true);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());

  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendBoolToUMA(metrics::kFpSensorErrorNoIrq, false))
      .Times(1);
  biod_metrics_.SendFpSensorErrorNoIrq(false);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());
}

TEST_F(BiodMetricsTest, SendFpSensorErrorSpiCommunication) {
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendBoolToUMA(metrics::kFpSensorErrorSpiCommunication, true))
      .Times(1);
  biod_metrics_.SendFpSensorErrorSpiCommunication(true);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());

  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendBoolToUMA(metrics::kFpSensorErrorSpiCommunication, false))
      .Times(1);
  biod_metrics_.SendFpSensorErrorSpiCommunication(false);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());
}

TEST_F(BiodMetricsTest, SendFpSensorErrorBadHardwareID) {
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendBoolToUMA(metrics::kFpSensorErrorBadHardwareID, true))
      .Times(1);
  biod_metrics_.SendFpSensorErrorBadHardwareID(true);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());

  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendBoolToUMA(metrics::kFpSensorErrorBadHardwareID, false))
      .Times(1);
  biod_metrics_.SendFpSensorErrorBadHardwareID(false);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());
}

TEST_F(BiodMetricsTest, SendFpSensorErrorInitializationFailure) {
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendBoolToUMA(metrics::kFpSensorErrorInitializationFailure, true))
      .Times(1);
  biod_metrics_.SendFpSensorErrorInitializationFailure(true);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());

  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendBoolToUMA(metrics::kFpSensorErrorInitializationFailure, false))
      .Times(1);
  biod_metrics_.SendFpSensorErrorInitializationFailure(false);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());
}

TEST_F(BiodMetricsTest, SendSessionRetirevePrimarySessionResult) {
  const auto result =
      BiodMetrics::RetrievePrimarySessionResult::kErrorDBusNoReply;

  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendEnumToUMA(metrics::kSessionRetrievePrimarySessionResult,
                            base::to_underlying(result), 7))
      .Times(1);

  biod_metrics_.SendSessionRetrievePrimarySessionResult(result);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());
}

TEST_F(BiodMetricsTest, SendSessionRetrievePrimarySessionDuration) {
  const int ms = 9999;
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(metrics::kSessionRetrievePrimarySessionDuration, ms, 0,
                        25000, 50))
      .Times(1);

  biod_metrics_.SendSessionRetrievePrimarySessionDuration(ms);
  testing::Mock::VerifyAndClearExpectations(GetMetricsLibraryMock());
}

}  // namespace
}  // namespace biod
