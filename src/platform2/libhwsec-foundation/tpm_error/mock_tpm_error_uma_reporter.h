// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_TPM_ERROR_MOCK_TPM_ERROR_UMA_REPORTER_H_
#define LIBHWSEC_FOUNDATION_TPM_ERROR_MOCK_TPM_ERROR_UMA_REPORTER_H_

#include "libhwsec-foundation/tpm_error/tpm_error_uma_reporter.h"

#include "libhwsec-foundation/hwsec-foundation_export.h"
#include "libhwsec-foundation/tpm_error/tpm_error_data.h"

namespace hwsec_foundation {

// Reports various types of UMA regarding to TPM errors.
class HWSEC_FOUNDATION_EXPORT MockTpmErrorUmaReporter
    : public TpmErrorUmaReporter {
 public:
  MockTpmErrorUmaReporter() = default;
  ~MockTpmErrorUmaReporter() override = default;

  MOCK_METHOD(void, Report, (const TpmErrorData&), (override));
  MOCK_METHOD(bool,
              ReportTpm2CommandAndResponse,
              (const TpmErrorData&),
              (override));
  MOCK_METHOD(bool,
              ReportTpm1CommandAndResponse,
              (const TpmErrorData&),
              (override));
};

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_TPM_ERROR_MOCK_TPM_ERROR_UMA_REPORTER_H_
