// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/biod_proxy/util.h"

#include "biod/proto_bindings/messages.pb.h"

namespace biod {

const char* ScanResultToString(ScanResult result) {
  switch (result) {
    case ScanResult::SCAN_RESULT_SUCCESS:
      return "Success";
    case ScanResult::SCAN_RESULT_PARTIAL:
      return "Partial";
    case ScanResult::SCAN_RESULT_INSUFFICIENT:
      return "Insufficient";
    case ScanResult::SCAN_RESULT_SENSOR_DIRTY:
      return "Sensor Dirty";
    case ScanResult::SCAN_RESULT_TOO_SLOW:
      return "Too Slow";
    case ScanResult::SCAN_RESULT_TOO_FAST:
      return "Too Fast";
    case ScanResult::SCAN_RESULT_IMMOBILE:
      return "Immobile";
    case ScanResult::SCAN_RESULT_NO_MATCH:
      return "No Match";
    default:
      return "Unknown Result";
  }
}

const char* FingerprintErrorToString(const FingerprintError& error) {
  switch (error) {
    case FingerprintError::ERROR_HW_UNAVAILABLE:
      return "Hardware unavailable";
    case FingerprintError::ERROR_UNABLE_TO_PROCESS:
      return "Operation can't continue";
    case FingerprintError::ERROR_TIMEOUT:
      return "Timeout";
    case FingerprintError::ERROR_NO_SPACE:
      return "No space for a template";
    case FingerprintError::ERROR_CANCELED:
      return "Canceled";
    case FingerprintError::ERROR_UNABLE_TO_REMOVE:
      return "Unable to remove a template";
    case FingerprintError::ERROR_LOCKOUT:
      return "Hardware is locked";
    case FingerprintError::ERROR_NO_TEMPLATES:
      return "No templates to match";
    default:
      return "Unknown error";
  }
}

}  // namespace biod
