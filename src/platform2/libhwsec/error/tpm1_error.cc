// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>

#include <trousers/trousers.h>
#include <base/strings/stringprintf.h>

#include "libhwsec/error/tpm1_error.h"

// trousers_types.h
#define TSS_ERROR_LAYER(x) (x & 0x3000)
#define TSS_ERROR_CODE(x) (x & TSS_MAX_ERROR)

namespace {

std::string FormatTrousersErrorCode(TSS_RESULT result) {
  return base::StringPrintf("TPM error 0x%x (%s)", result,
                            Trspi_Error_String(result));
}

}  // namespace

namespace hwsec {

TPM1Error::TPM1Error(TSS_RESULT error_code)
    : TPMErrorBase(FormatTrousersErrorCode(error_code)),
      error_code_(error_code) {}

TPMRetryAction TPM1Error::ToTPMRetryAction() const {
  if (TSS_ERROR_CODE(error_code_) == TSS_SUCCESS) {
    return TPMRetryAction::kNone;
  }

  switch (TSS_ERROR_LAYER(error_code_)) {
    case TSS_LAYER_TPM:
      switch (TSS_ERROR_CODE(error_code_)) {
        // Invalid handle to the TPM.
        case TPM_E_INVALID_AUTHHANDLE:
          return TPMRetryAction::kLater;
        // The TPM is defending itself against possible dictionary attacks.
        case TPM_E_DEFEND_LOCK_RUNNING:
          return TPMRetryAction::kDefend;
        // TPM is out of memory, a reboot is needed.
        case TPM_E_SIZE:
          return TPMRetryAction::kReboot;
        // The TPM returned TPM_E_FAIL. A reboot is required.
        case TPM_E_FAIL:
          return TPMRetryAction::kReboot;
        // Retrying will not help.
        default:
          return TPMRetryAction::kNoRetry;
      }
    case TSS_LAYER_TCS:
      switch (TSS_ERROR_CODE(error_code_)) {
        // Communications failure with the TPM.
        case TSS_E_COMM_FAILURE:
          return TPMRetryAction::kCommunication;
        // Key load failed; problem with parent key authorization.
        case TCS_E_KM_LOADFAILED:
          return TPMRetryAction::kLater;
        // Retrying will not help.
        default:
          return TPMRetryAction::kNoRetry;
      }
      break;
    case TSS_LAYER_TSP:
      switch (TSS_ERROR_CODE(error_code_)) {
        // Communications failure with the TPM.
        case TSS_E_COMM_FAILURE:
          return TPMRetryAction::kCommunication;
        // Invalid handle to the TPM.
        case TSS_E_INVALID_HANDLE:
          return TPMRetryAction::kLater;
        // Retrying will not help.
        default:
          return TPMRetryAction::kNoRetry;
      }
      break;
    default:
      switch (TSS_ERROR_CODE(error_code_)) {
        // Communications failure with the TPM.
        case TSS_E_COMM_FAILURE:
          return TPMRetryAction::kCommunication;
        // Retrying will not help.
        default:
          return TPMRetryAction::kNoRetry;
      }
  }
}

}  // namespace hwsec
