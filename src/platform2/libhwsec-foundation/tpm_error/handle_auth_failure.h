// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_TPM_ERROR_HANDLE_AUTH_FAILURE_H_
#define LIBHWSEC_FOUNDATION_TPM_ERROR_HANDLE_AUTH_FAILURE_H_

#include <stddef.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"
#include "libhwsec-foundation/tpm_error/tpm_error_data.h"

#if defined(__cplusplus)
extern "C" {
#endif

// Iff there was an error while processing the AuthFailure functions
// store the error messages into |out| and return 1.
HWSEC_FOUNDATION_EXPORT int FetchAuthFailureError(char* out, size_t size);

// Set the log path for the auth failure logging.
// |log_path| is only for current life cycle, and |permanent_log_path| is for
// all life cycle.
HWSEC_FOUNDATION_EXPORT void InitializeAuthFailureLogging(
    const char* log_path, const char* permanent_log_path);

// Iff there is any entry in |current_path| of the previous life cycle,
// move the entries to |previous_path| and return 1.
HWSEC_FOUNDATION_EXPORT int CheckAuthFailureHistory(const char* current_path,
                                                    const char* previous_path,
                                                    size_t* auth_failure_hash);

// Handles the auth failure if necessary accordring to `data`, including
// resetting DA mitigation and error reporting.
HWSEC_FOUNDATION_EXPORT int HandleAuthFailure(const struct TpmErrorData* data);

#if defined(__cplusplus)
}
#endif

#endif  // LIBHWSEC_FOUNDATION_TPM_ERROR_HANDLE_AUTH_FAILURE_H_
