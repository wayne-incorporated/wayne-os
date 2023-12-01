// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_BIOD_METRICS_H_
#define BIOD_BIOD_METRICS_H_

#include <memory>
#include <utility>

#include <libec/fingerprint/cros_fp_device_interface.h>
#include <libec/fingerprint/fp_mode.h>
#include <metrics/metrics_library.h>

#include "biod/updater/update_reason.h"

namespace biod {

namespace metrics {

inline constexpr char kFpUnlockEnabled[] = "Fingerprint.UnlockEnabled";
inline constexpr char kFpEnrolledFingerCount[] =
    "Fingerprint.Unlock.EnrolledFingerCount";
inline constexpr char kFpEnrollmentCapturesCount[] =
    "Fingerprint.Enroll.NumCaptures";
inline constexpr char kFpMatchDurationCapture[] =
    "Fingerprint.Unlock.Match.Duration.Capture";
inline constexpr char kFpMatchDurationMatcher[] =
    "Fingerprint.Unlock.Match.Duration.Matcher";
inline constexpr char kFpMatchDurationOverall[] =
    "Fingerprint.Unlock.Match.Duration.Overall";
inline constexpr char kFpNoMatchDurationCapture[] =
    "Fingerprint.Unlock.NoMatch.Duration.Capture";
inline constexpr char kFpNoMatchDurationMatcher[] =
    "Fingerprint.Unlock.NoMatch.Duration.Matcher";
inline constexpr char kFpNoMatchDurationOverall[] =
    "Fingerprint.Unlock.NoMatch.Duration.Overall";
inline constexpr char kFpMatchIgnoredDueToPowerButtonPress[] =
    "Fingerprint.Unlock.MatchIgnoredDueToPowerButtonPress";
inline constexpr char kResetContextMode[] =
    "Fingerprint.Reset.ResetContextMode";
inline constexpr char kSetContextMode[] =
    "Fingerprint.SetContext.SetContextMode";
inline constexpr char kSetContextSuccess[] = "Fingerprint.SetContext.Success";
inline constexpr char kUpdaterStatus[] = "Fingerprint.Updater.Status";
inline constexpr char kUpdaterReason[] = "Fingerprint.Updater.Reason";
inline constexpr char kUpdaterDurationNoUpdate[] =
    "Fingerprint.Updater.NoUpdate.Duration.Overall";
inline constexpr char kUpdaterDurationUpdate[] =
    "Fingerprint.Updater.Update.Duration.Overall";
inline constexpr char kFpReadPositiveMatchSecretSuccessOnMatch[] =
    "Fingerprint.Unlock.ReadPositiveMatchSecret.Success";
inline constexpr char kFpPositiveMatchSecretCorrect[] =
    "Fingerprint.Unlock.Match.PositiveMatchSecretCorrect";
inline constexpr char kRecordFormatVersionMetric[] =
    "Fingerprint.Unlock.RecordFormatVersion";
inline constexpr char kNumDeadPixels[] = "Fingerprint.Sensor.NumDeadPixels";
inline constexpr char kUploadTemplateSuccess[] =
    "Fingerprint.UploadTemplate.Success";
inline constexpr char kPartialAttemptsBeforeSuccess[] =
    "Fingerprint.Unlock.PartialAttemptsBeforeSuccess";
inline constexpr char kFpSensorErrorNoIrq[] = "Fingerprint.SensorError.NoIrq";
inline constexpr char kFpSensorErrorSpiCommunication[] =
    "Fingerprint.SensorError.SpiCommunication";
inline constexpr char kFpSensorErrorBadHardwareID[] =
    "Fingerprint.SensorError.BadHwid";
inline constexpr char kFpSensorErrorInitializationFailure[] =
    "Fingerprint.SensorError.InitializationFailure";
inline constexpr char kSessionRetrievePrimarySessionResult[] =
    "Fingerprint.Session.RetrievePrimarySessionResult";
inline constexpr char kSessionRetrievePrimarySessionDuration[] =
    "Fingerprint.Session.RetrievePrimarySessionDuration";

// Special value to send to UMA on EC command related metrics.
inline constexpr int kCmdRunFailure = -1;

}  // namespace metrics

class BiodMetricsInterface {
 public:
  virtual ~BiodMetricsInterface() = default;

  // This is the tools/bio_fw_updater overall status,
  // which encapsulates an UpdateStatus.
  enum class FwUpdaterStatus : int {
    kUnnecessary = 0,
    kSuccessful = 1,
    kFailureFirmwareFileMultiple = 2,
    kFailureFirmwareFileNotFound = 3,
    kFailureFirmwareFileOpen = 4,
    kFailureFirmwareFileFmap = 5,
    kFailurePreUpdateVersionCheck = 6,
    kFailurePostUpdateVersionCheck = 7,
    kFailureUpdateVersionCheck = 8,
    kFailureUpdateFlashProtect = 9,
    kFailureUpdateRO = 10,
    kFailureUpdateRW = 11,

    // TODO(b/266077024) Change UMA enum name kUpdaterStatus if new enums
    // are added to avoid data discontinuity.
    kMaxValue = kFailureUpdateRW,
  };

  // This enum is tied directly to a UMA enum defined in
  // tools/metrics/histograms/enums.xml, existing entries should not be
  // modified.
  enum class RetrievePrimarySessionResult : int {
    kSuccess = 0,
    kErrorUnknown = 1,
    kErrorDBusNoReply = 2,
    kErrorDBusServiceUnknown = 3,
    kErrorResponseMissing = 4,
    kErrorParsing = 5,

    kMaxValue = kErrorParsing + 1,
  };

  virtual bool SendEnrolledFingerCount(int finger_count) = 0;
  virtual bool SendEnrollmentCapturesCount(int captures_count) = 0;
  virtual bool SendFpUnlockEnabled(bool enabled) = 0;
  virtual bool SendFpLatencyStats(
      bool matched, const ec::CrosFpDeviceInterface::FpStats& stats) = 0;
  virtual bool SendFwUpdaterStatus(FwUpdaterStatus status,
                                   updater::UpdateReason reason,
                                   int overall_ms) = 0;
  virtual bool SendIgnoreMatchEventOnPowerButtonPress(bool is_ignored) = 0;
  virtual bool SendResetContextMode(const ec::FpMode& mode) = 0;
  virtual bool SendSetContextMode(const ec::FpMode& mode) = 0;
  virtual bool SendSetContextSuccess(bool success) = 0;
  virtual bool SendReadPositiveMatchSecretSuccess(bool success) = 0;
  virtual bool SendPositiveMatchSecretCorrect(bool correct) = 0;
  virtual bool SendRecordFormatVersion(int version) = 0;
  virtual bool SendDeadPixelCount(int num_dead_pixels) = 0;
  virtual bool SendUploadTemplateResult(int ec_result) = 0;
  virtual bool SendPartialAttemptsBeforeSuccess(int partial_attempts) = 0;
  virtual bool SendFpSensorErrorNoIrq(bool no_irq) = 0;
  virtual bool SendFpSensorErrorSpiCommunication(
      bool spi_communication_error) = 0;
  virtual bool SendFpSensorErrorBadHardwareID(bool bad_hwid) = 0;
  virtual bool SendFpSensorErrorInitializationFailure(bool init_failure) = 0;
  virtual bool SendSessionRetrievePrimarySessionResult(
      RetrievePrimarySessionResult result) = 0;
  virtual bool SendSessionRetrievePrimarySessionDuration(int ms) = 0;
};

class BiodMetrics : public BiodMetricsInterface {
 public:
  BiodMetrics();
  BiodMetrics(const BiodMetrics&) = delete;
  BiodMetrics& operator=(const BiodMetrics&) = delete;

  ~BiodMetrics() override = default;

  // Send number of fingers enrolled.
  bool SendEnrolledFingerCount(int finger_count) override;

  // Send number of enrollment captures.
  bool SendEnrollmentCapturesCount(int captures_count) override;

  // Is unlocking with FP enabled or not?
  bool SendFpUnlockEnabled(bool enabled) override;

  // Send matching/capture latency metrics.
  bool SendFpLatencyStats(
      bool matched, const ec::CrosFpDeviceInterface::FpStats& stats) override;

  bool SendFwUpdaterStatus(FwUpdaterStatus status,
                           updater::UpdateReason reason,
                           int overall_ms) override;

  // Is fingerprint ignored due to parallel power button press?
  bool SendIgnoreMatchEventOnPowerButtonPress(bool is_ignored) override;

  // Was CrosFpDevice::ResetContext called while the FPMCU was in correct mode?
  bool SendResetContextMode(const ec::FpMode& mode) override;

  // What mode was FPMCU in when we set context?
  bool SendSetContextMode(const ec::FpMode& mode) override;

  // Did setting context succeed?
  bool SendSetContextSuccess(bool success) override;

  // Reading positive match secret succeeded or not?
  bool SendReadPositiveMatchSecretSuccess(bool success) override;

  // Positive match secret is as expected or not?
  bool SendPositiveMatchSecretCorrect(bool correct) override;

  // Template record file format version.
  bool SendRecordFormatVersion(int version) override;

  bool SendDeadPixelCount(int num_dead_pixels) override;

  // Return code of FP_TEMPLATE EC command
  bool SendUploadTemplateResult(int ec_result) override;

  // We allow up to 20 attempts without reporting error if the match result is
  // EC_MKBP_FP_ERR_MATCH_NO_LOW_COVERAGE. This counts how many partial attempts
  // is actually used before each successful match.
  bool SendPartialAttemptsBeforeSuccess(int partial_attempts) override;

  bool SendFpSensorErrorNoIrq(bool no_irq) override;
  bool SendFpSensorErrorSpiCommunication(bool spi_communication_error) override;
  bool SendFpSensorErrorBadHardwareID(bool bad_hwid) override;
  bool SendFpSensorErrorInitializationFailure(bool init_failure) override;

  // SessionStateManager metrics.
  bool SendSessionRetrievePrimarySessionResult(
      RetrievePrimarySessionResult result) override;
  bool SendSessionRetrievePrimarySessionDuration(int ms) override;

  void SetMetricsLibraryForTesting(
      std::unique_ptr<MetricsLibraryInterface> metrics_lib);

  MetricsLibraryInterface* metrics_library_for_testing() {
    return metrics_lib_.get();
  }

 private:
  std::unique_ptr<MetricsLibraryInterface> metrics_lib_;
};

}  // namespace biod

#endif  // BIOD_BIOD_METRICS_H_
