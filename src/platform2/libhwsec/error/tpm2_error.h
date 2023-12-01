// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_ERROR_TPM2_ERROR_H_
#define LIBHWSEC_ERROR_TPM2_ERROR_H_

#include <memory>
#include <string>
#include <utility>

#include <trunks/error_codes.h>

#include "libhwsec/error/tpm_error.h"
#include "libhwsec/hwsec_export.h"

namespace hwsec {

// The error handler object for TPM2.
class HWSEC_EXPORT TPM2Error : public TPMErrorBase {
 public:
  struct MakeStatusTrait {
    auto operator()(trunks::TPM_RC error_code) {
      using hwsec_foundation::status::NewStatus;
      using hwsec_foundation::status::OkStatus;

      if (error_code != trunks::TPM_RC_SUCCESS) {
        return NewStatus<TPM2Error>(error_code);
      }
      return OkStatus<TPM2Error>();
    }
  };

  explicit TPM2Error(trunks::TPM_RC error_code);
  ~TPM2Error() override = default;
  TPMRetryAction ToTPMRetryAction() const override;
  trunks::TPM_RC ErrorCode() const { return error_code_; }
  unified_tpm_error::UnifiedError UnifiedErrorCode() const override {
    // TPM 2.0 error code is 16 bits, with bit 12-15 being the layer bit
    unified_tpm_error::UnifiedError error_code =
        static_cast<unified_tpm_error::UnifiedError>(error_code_);
    DCHECK_EQ(error_code & (~unified_tpm_error::kUnifiedErrorMask), 0);
    return error_code | unified_tpm_error::kUnifiedErrorBit;
  }

  void LogUnifiedErrorCodeMapping() const override {}

 private:
  const trunks::TPM_RC error_code_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_ERROR_TPM2_ERROR_H_
