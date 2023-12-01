// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_MOCK_BIOD_METRICS_H_
#define BIOD_MOCK_BIOD_METRICS_H_

#include <gmock/gmock.h>

#include "biod/biod_metrics.h"

namespace biod {
namespace metrics {

class MockBiodMetrics : public BiodMetricsInterface {
 public:
  MockBiodMetrics() = default;
  ~MockBiodMetrics() override = default;

  MOCK_METHOD(bool, SendEnrolledFingerCount, (int finger_count), (override));
  MOCK_METHOD(bool,
              SendEnrollmentCapturesCount,
              (int captures_count),
              (override));
  MOCK_METHOD(bool, SendFpUnlockEnabled, (bool enabled), (override));
  MOCK_METHOD(bool,
              SendFpLatencyStats,
              (bool matched, const ec::CrosFpDeviceInterface::FpStats& stats),
              (override));
  MOCK_METHOD(bool,
              SendFwUpdaterStatus,
              (FwUpdaterStatus status,
               updater::UpdateReason reason,
               int overall_ms),
              (override));
  MOCK_METHOD(bool,
              SendIgnoreMatchEventOnPowerButtonPress,
              (bool is_ignored),
              (override));
  MOCK_METHOD(bool, SendResetContextMode, (const ec::FpMode& mode), (override));
  MOCK_METHOD(bool, SendSetContextMode, (const ec::FpMode& mode), (override));
  MOCK_METHOD(bool, SendSetContextSuccess, (bool success), (override));
  MOCK_METHOD(bool,
              SendReadPositiveMatchSecretSuccess,
              (bool success),
              (override));
  MOCK_METHOD(bool, SendPositiveMatchSecretCorrect, (bool correct), (override));
  MOCK_METHOD(bool, SendRecordFormatVersion, (int version), (override));
  MOCK_METHOD(bool, SendDeadPixelCount, (int num_dead_pixels), (override));
  MOCK_METHOD(bool, SendUploadTemplateResult, (int ec_result), (override));
  MOCK_METHOD(bool,
              SendPartialAttemptsBeforeSuccess,
              (int partial_attempts),
              (override));
  MOCK_METHOD(bool, SendFpSensorErrorNoIrq, (bool no_irq), (override));
  MOCK_METHOD(bool,
              SendFpSensorErrorSpiCommunication,
              (bool spi_communication_error),
              (override));
  MOCK_METHOD(bool,
              SendFpSensorErrorBadHardwareID,
              (bool bad_hwid),
              (override));
  MOCK_METHOD(bool,
              SendFpSensorErrorInitializationFailure,
              (bool init_failure),
              (override));
  MOCK_METHOD(bool,
              SendSessionRetrievePrimarySessionResult,
              (RetrievePrimarySessionResult result),
              (override));
  MOCK_METHOD(bool,
              SendSessionRetrievePrimarySessionDuration,
              (int ms),
              (override));
};

}  // namespace metrics
}  // namespace biod

#endif  // BIOD_MOCK_BIOD_METRICS_H_
