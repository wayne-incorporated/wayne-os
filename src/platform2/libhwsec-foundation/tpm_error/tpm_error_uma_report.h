// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_TPM_ERROR_TPM_ERROR_UMA_REPORT_H_
#define LIBHWSEC_FOUNDATION_TPM_ERROR_TPM_ERROR_UMA_REPORT_H_

#include "libhwsec-foundation/hwsec-foundation_export.h"
#include "libhwsec-foundation/tpm_error/tpm_error_data.h"

#if defined(__cplusplus)
extern "C" {
#endif

// Report the TPM1 command and response. The |data|.command should be less
// then 2^12 and the |data|.response should be less then 2^16.
HWSEC_FOUNDATION_EXPORT int ReportTpm1CommandAndResponse(
    const struct TpmErrorData* data);

#if defined(__cplusplus)
}
#endif

#endif  // LIBHWSEC_FOUNDATION_TPM_ERROR_TPM_ERROR_UMA_REPORT_H_
