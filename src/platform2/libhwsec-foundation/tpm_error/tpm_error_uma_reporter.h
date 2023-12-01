// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_TPM_ERROR_TPM_ERROR_UMA_REPORTER_H_
#define LIBHWSEC_FOUNDATION_TPM_ERROR_TPM_ERROR_UMA_REPORTER_H_

#include <string>

#include <metrics/metrics_library.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"
#include "libhwsec-foundation/tpm_error/tpm_error_data.h"

namespace hwsec_foundation {

enum class HWSEC_FOUNDATION_EXPORT TpmMetricsClientID {
  kUnknown = 0,
  kCryptohome = 1,
  kAttestation = 2,
  kTpmManager = 3,
  kChaps = 4,
  kVtpm = 5,
  kU2f = 6,
  kTrunksSend = 7,
};

void HWSEC_FOUNDATION_EXPORT SetTpmMetricsClientID(TpmMetricsClientID id);
TpmMetricsClientID HWSEC_FOUNDATION_EXPORT GetTpmMetricsClientID();

// Reports various types of UMA regarding to TPM errors.
class HWSEC_FOUNDATION_EXPORT TpmErrorUmaReporter {
 public:
  virtual ~TpmErrorUmaReporter() = default;

  // Reports the UMAs according to the error indicated in `data`, if necessary.
  virtual void Report(const TpmErrorData& data) = 0;

  // Report the TPM command and response. The |data|.command should be less
  // then 2^12 and the |data|.response should be less then 2^16.
  virtual bool ReportTpm1CommandAndResponse(const TpmErrorData& data) = 0;
  virtual bool ReportTpm2CommandAndResponse(const TpmErrorData& data) = 0;
};

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_TPM_ERROR_TPM_ERROR_UMA_REPORTER_H_
