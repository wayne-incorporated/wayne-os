// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_TPM_ERROR_AUTH_FAILURE_ANALYSIS_H_
#define LIBHWSEC_FOUNDATION_TPM_ERROR_AUTH_FAILURE_ANALYSIS_H_

#include "libhwsec-foundation/hwsec-foundation_export.h"
#include "libhwsec-foundation/tpm_error/tpm_error_data.h"

namespace hwsec_foundation {

// Tells if the DA counter increases according to `data`; for TPM2.0, it is not
// implemented and always return `false`.
HWSEC_FOUNDATION_EXPORT bool DoesCauseDAIncrease(const TpmErrorData& data);

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_TPM_ERROR_AUTH_FAILURE_ANALYSIS_H_
