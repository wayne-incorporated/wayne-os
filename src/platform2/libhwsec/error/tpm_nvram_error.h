// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_ERROR_TPM_NVRAM_ERROR_H_
#define LIBHWSEC_ERROR_TPM_NVRAM_ERROR_H_

#include <memory>
#include <string>
#include <utility>
#include <variant>

#include <tpm_manager/proto_bindings/tpm_manager.pb.h>

#include "libhwsec/error/tpm_error.h"
#include "libhwsec/hwsec_export.h"

namespace hwsec {

// The error handler object for TPM NVRAM result.
class HWSEC_EXPORT TPMNvramError : public TPMErrorBase {
 public:
  using NvramResult = tpm_manager::NvramResult;

  struct MakeStatusTrait {
    auto operator()(NvramResult error_code) {
      using hwsec_foundation::status::NewStatus;
      using hwsec_foundation::status::OkStatus;

      if (error_code != NvramResult::NVRAM_RESULT_SUCCESS) {
        return NewStatus<TPMNvramError>(error_code);
      }
      return OkStatus<TPMNvramError>();
    }
  };

  explicit TPMNvramError(NvramResult error_code);
  ~TPMNvramError() override = default;
  TPMRetryAction ToTPMRetryAction() const override;
  NvramResult ErrorCode() const { return error_code_; }

  unified_tpm_error::UnifiedError UnifiedErrorCode() const override {
    unified_tpm_error::UnifiedError error_code =
        static_cast<unified_tpm_error::UnifiedError>(error_code_);
    error_code += unified_tpm_error::kUnifiedErrorNvramBase;
    DCHECK_LT(error_code, unified_tpm_error::kUnifiedErrorNvramMax);
    return error_code;
  }

  void LogUnifiedErrorCodeMapping() const override {}

 private:
  const NvramResult error_code_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_ERROR_TPM_NVRAM_ERROR_H_
