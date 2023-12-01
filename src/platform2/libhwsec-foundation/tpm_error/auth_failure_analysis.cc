// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/tpm_error/auth_failure_analysis.h"

#include "libhwsec-foundation/tpm/tpm_version.h"
#include "libhwsec-foundation/tpm_error/tpm_error_constants.h"
#include "libhwsec-foundation/tpm_error/tpm_error_data.h"

namespace hwsec_foundation {

bool DoesCauseDAIncrease(const TpmErrorData& data) {
  // For TPM2.0 case, the reactive trigger model of DA reset is not implemented;
  // thus, always returns `false`.
  TPM_SELECT_BEGIN;
  TPM2_SECTION({ return false; });
  TPM1_SECTION({
    return data.response == kTpm1Auth2FailResponse ||
           data.response == kTpm1AuthFailResponse;
  });
  OTHER_TPM_SECTION();
  TPM_SELECT_END;
  return false;
}

}  // namespace hwsec_foundation
