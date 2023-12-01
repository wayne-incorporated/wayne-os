// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>

#include <base/strings/stringprintf.h>

#include "libhwsec/error/tpm_nvram_error.h"

using tpm_manager::NvramResult;

namespace {

const char* NvramResultString(NvramResult error_code) {
  switch (error_code) {
    case NvramResult::NVRAM_RESULT_SUCCESS:
      return "NVRAM_RESULT_SUCCESS";
    case NvramResult::NVRAM_RESULT_DEVICE_ERROR:
      return "NVRAM_RESULT_DEVICE_ERROR";
    case NvramResult::NVRAM_RESULT_ACCESS_DENIED:
      return "NVRAM_RESULT_ACCESS_DENIED";
    case NvramResult::NVRAM_RESULT_INVALID_PARAMETER:
      return "NVRAM_RESULT_INVALID_PARAMETER";
    case NvramResult::NVRAM_RESULT_SPACE_DOES_NOT_EXIST:
      return "NVRAM_RESULT_SPACE_DOES_NOT_EXIST";
    case NvramResult::NVRAM_RESULT_SPACE_ALREADY_EXISTS:
      return "NVRAM_RESULT_SPACE_ALREADY_EXISTS";
    case NvramResult::NVRAM_RESULT_OPERATION_DISABLED:
      return "NVRAM_RESULT_OPERATION_DISABLED";
    case NvramResult::NVRAM_RESULT_INSUFFICIENT_SPACE:
      return "NVRAM_RESULT_INSUFFICIENT_SPACE";
    case NvramResult::NVRAM_RESULT_IPC_ERROR:
      return "NVRAM_RESULT_IPC_ERROR";
    default:
      return "";
  }
}

std::string FormatNvramResult(NvramResult result) {
  return base::StringPrintf("NVRAM result %d (%s)", result,
                            NvramResultString(result));
}

}  // namespace

namespace hwsec {

TPMNvramError::TPMNvramError(NvramResult error_code)
    : TPMErrorBase(FormatNvramResult(error_code)), error_code_(error_code) {}

TPMRetryAction TPMNvramError::ToTPMRetryAction() const {
  switch (error_code_) {
    case NvramResult::NVRAM_RESULT_SUCCESS:
      return TPMRetryAction::kNone;
    // Reboot may be helpful for these failure.
    case NvramResult::NVRAM_RESULT_DEVICE_ERROR:
      return TPMRetryAction::kReboot;
    // Retry later may be helpful for this failure.
    case NvramResult::NVRAM_RESULT_INSUFFICIENT_SPACE:
      return TPMRetryAction::kLater;
    // Communications failure.
    case NvramResult::NVRAM_RESULT_IPC_ERROR:
      return TPMRetryAction::kCommunication;
    // Space not fount.
    case NvramResult::NVRAM_RESULT_SPACE_DOES_NOT_EXIST:
      return TPMRetryAction::kSpaceNotFound;
    // Retrying will not help.
    case NvramResult::NVRAM_RESULT_ACCESS_DENIED:
    case NvramResult::NVRAM_RESULT_INVALID_PARAMETER:
    case NvramResult::NVRAM_RESULT_SPACE_ALREADY_EXISTS:
    case NvramResult::NVRAM_RESULT_OPERATION_DISABLED:
    default:
      return TPMRetryAction::kNoRetry;
  }
}

}  // namespace hwsec
