// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_LOGS_LOGS_CONSTANTS_H_
#define RMAD_LOGS_LOGS_CONSTANTS_H_

#include <string>

#include <base/containers/fixed_flat_map.h>
#include <base/strings/string_piece.h>

namespace rmad {

// JsonStore keys.
inline constexpr char kLogs[] = "logs";
inline constexpr char kEvents[] = "events";

// Event keys.
inline constexpr char kTimestamp[] = "timestamp";
inline constexpr char kStateId[] = "state_id";
inline constexpr char kType[] = "type";
inline constexpr char kDetails[] = "details";

// State transition keys.
inline constexpr char kFromStateId[] = "from_state_id";
inline constexpr char kToStateId[] = "to_state_id";

// Error keys.
inline constexpr char kOccurredError[] = "occurred_error";

// State specific attributes.
inline constexpr char kLogIsCompliant[] = "is_compliant";
inline constexpr char kLogUnqualifiedComponents[] = "unqualified_components";
inline constexpr char kLogReplacedComponents[] = "replaced_components";
inline constexpr char kLogReworkSelected[] = "rework_selected";
inline constexpr char kLogDestination[] = "destination";
inline constexpr char kLogWipeDevice[] = "wipe_device";
inline constexpr char kLogWpDisableMethod[] = "wp_disable_method";
inline constexpr char kLogRsuChallengeCode[] = "challenge_code";
inline constexpr char kLogRsuHwid[] = "hwid";
inline constexpr char kLogRestockOption[] = "restock_option";
inline constexpr char kLogCalibrationComponents[] = "calibration_components";
inline constexpr char kLogCalibrationSetupInstruction[] =
    "calibration_instruction";
inline constexpr char kLogComponent[] = "component";
inline constexpr char kLogCalibrationStatus[] = "calibration_status";
inline constexpr char kFirmwareStatus[] = "firmware_status";

// Log string formats.
constexpr char kLogTimestampFormat[] = "[%04d-%02d-%02d %02d:%02d:%02d] ";
constexpr char kLogTransitionFormat[] = "Transitioned from %s to %s";
constexpr char kLogErrorFormat[] = "ERROR in %s: %s";
constexpr char kLogDetailPrefixFormat[] = "%s: ";
constexpr char kLogRepairStartString[] = "Shimless RMA Started";
constexpr char kLogNoUnqualifiedComponentsString[] =
    "No unqualified components detected";
constexpr char kLogUnqualifiedComponentsDetectedFormat[] =
    "Unqualified components detected - %s";
constexpr char kLogSelectComponentsFormat[] = "Selected %s";
constexpr char kLogSelectComponentsReworkString[] = "Selected Mainboard Rework";
constexpr char kLogChooseDeviceDestinationFormat[] = "Selected %s";
constexpr char kLogWipeSelectionFormat[] = "Selected to %s user data";
constexpr char kLogWpDisableFormat[] =
    "Selected to disable write protect via %s";
constexpr char kLogRsuChallengeFormat[] = "The RSU challenge code is %s";
constexpr char kLogRestockContinueString[] = "Continuing";
constexpr char kLogRestockShutdownString[] = "Shutting down the device";
constexpr char kLogCalibrationSetupBaseString[] = "Place base on flat surface";
constexpr char kLogCalibrationSetupLidString[] = "Place lid on flat surface";
constexpr char kLogCalibrationSetupUnknownString[] = "Unknown";
constexpr char kLogCalibrationFormat[] = "Calibration for %s";
constexpr char kLogCalibrationStatusFailedString[] = "Failed";
constexpr char kLogCalibrationStatusSkippedString[] = "Skipped";
constexpr char kLogCalibrationStatusRetriedString[] = "Retried";
constexpr char kLogFirmwareUpdatePluggedInString[] = "Plugged in USB";
constexpr char kLogFirmwareUpdateFileNotFoundString[] =
    "Suitable OS image not detected on USB";
constexpr char kFirmwareUpdatedString[] = "Firmware updated. Going to reboot";
constexpr char kFirmwareCompleteString[] = "Firmware update complete";

enum class LogEventType {
  kTransition = 0,
  kData = 1,
  kError = 2,
  kMaxValue = kError,
};

enum class LogCalibrationStatus {
  kFailed = 0,
  kSkip = 1,
  kRetry = 2,
  kMaxValue = kRetry,
};

constexpr auto kLogCalibrationStatusMap =
    base::MakeFixedFlatMap<LogCalibrationStatus, base::StringPiece>(
        {{LogCalibrationStatus::kFailed, kLogCalibrationStatusFailedString},
         {LogCalibrationStatus::kSkip, kLogCalibrationStatusSkippedString},
         {LogCalibrationStatus::kRetry, kLogCalibrationStatusRetriedString}});

enum class FirmwareUpdateStatus {
  kUsbPluggedIn = 0,
  kUsbPluggedInFileNotFound = 1,
  kFirmwareUpdated = 2,
  kFirmwareComplete = 3,
  kMaxValue = kFirmwareComplete,
};

constexpr auto kFirmwareUpdateStatusMap =
    base::MakeFixedFlatMap<FirmwareUpdateStatus, base::StringPiece>(
        {{FirmwareUpdateStatus::kUsbPluggedIn,
          kLogFirmwareUpdatePluggedInString},
         {FirmwareUpdateStatus::kUsbPluggedInFileNotFound,
          kLogFirmwareUpdateFileNotFoundString},
         {FirmwareUpdateStatus::kFirmwareUpdated, kFirmwareUpdatedString},
         {FirmwareUpdateStatus::kFirmwareComplete, kFirmwareCompleteString}});

}  // namespace rmad

#endif  // RMAD_LOGS_LOGS_CONSTANTS_H_
