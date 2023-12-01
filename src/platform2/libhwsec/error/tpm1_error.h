// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_ERROR_TPM1_ERROR_H_
#define LIBHWSEC_ERROR_TPM1_ERROR_H_

#include <memory>
#include <string>
#include <utility>

#include <trousers/tss.h>

#include "libhwsec/error/tpm_error.h"
#include "libhwsec/hwsec_export.h"

namespace hwsec {

// The error handler object for TPM1.
class HWSEC_EXPORT TPM1Error : public TPMErrorBase {
 public:
  struct MakeStatusTrait {
    auto operator()(TSS_RESULT error_code) {
      using hwsec_foundation::status::NewStatus;
      using hwsec_foundation::status::OkStatus;

      if (error_code != TSS_SUCCESS) {
        return NewStatus<TPM1Error>(error_code);
      }
      return OkStatus<TPM1Error>();
    }
  };

  explicit TPM1Error(TSS_RESULT error_code);
  ~TPM1Error() override = default;
  TPMRetryAction ToTPMRetryAction() const override;
  TSS_RESULT ErrorCode() const { return error_code_; }
  unified_tpm_error::UnifiedError UnifiedErrorCode() const override {
    // TPM 1.2 error code is 16 bits, with bit 12-15 being the layer bit.
    unified_tpm_error::UnifiedError error_code =
        static_cast<unified_tpm_error::UnifiedError>(error_code_);
    DCHECK_EQ(error_code & (~unified_tpm_error::kUnifiedErrorMask), 0);
    return error_code | unified_tpm_error::kUnifiedErrorBit;
  }

  void LogUnifiedErrorCodeMapping() const override {}

 private:
  const TSS_RESULT error_code_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_ERROR_TPM1_ERROR_H_
