// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>

#include <base/strings/stringprintf.h>

#include "libhwsec/error/tpm_manager_error.h"

using tpm_manager::TpmManagerStatus;

namespace {

const char* TpmManagerStatusString(TpmManagerStatus error_code) {
  switch (error_code) {
    case TpmManagerStatus::STATUS_SUCCESS:
      return "STATUS_SUCCESS";
    case TpmManagerStatus::STATUS_DEVICE_ERROR:
      return "STATUS_DEVICE_ERROR";
    case TpmManagerStatus::STATUS_NOT_AVAILABLE:
      return "STATUS_NOT_AVAILABLE";
    case TpmManagerStatus::STATUS_DBUS_ERROR:
      return "STATUS_DBUS_ERROR";
    default:
      return "";
  }
}

std::string FormatTpmManagerStatus(TpmManagerStatus result) {
  return base::StringPrintf("TpmManager status %d (%s)", result,
                            TpmManagerStatusString(result));
}

}  // namespace

namespace hwsec {

TPMManagerError::TPMManagerError(TpmManagerStatus error_code)
    : TPMErrorBase(FormatTpmManagerStatus(error_code)),
      error_code_(error_code) {}

TPMRetryAction TPMManagerError::ToTPMRetryAction() const {
  switch (error_code_) {
    case TpmManagerStatus::STATUS_SUCCESS:
      return TPMRetryAction::kNone;
    // Reboot may be helpful for these failure.
    case TpmManagerStatus::STATUS_DEVICE_ERROR:
    case TpmManagerStatus::STATUS_NOT_AVAILABLE:
      return TPMRetryAction::kReboot;
    // Communications failure.
    case TpmManagerStatus::STATUS_DBUS_ERROR:
      return TPMRetryAction::kCommunication;
    // Retrying will not help.
    default:
      return TPMRetryAction::kNoRetry;
  }
}

}  // namespace hwsec
