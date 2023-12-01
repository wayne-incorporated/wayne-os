// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_TPM_ERROR_TPM_ERROR_UMA_REPORTER_IMPL_H_
#define LIBHWSEC_FOUNDATION_TPM_ERROR_TPM_ERROR_UMA_REPORTER_IMPL_H_

#include "libhwsec-foundation/tpm_error/tpm_error_uma_reporter.h"

#include <string>

#include <metrics/metrics_library.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"
#include "libhwsec-foundation/tpm_error/tpm_error_data.h"

namespace hwsec_foundation {

class HWSEC_FOUNDATION_EXPORT TpmErrorUmaReporterImpl
    : public TpmErrorUmaReporter {
 public:
  TpmErrorUmaReporterImpl() = default;
  // Constructs the object with injected `metrics`; used for testing.
  explicit TpmErrorUmaReporterImpl(MetricsLibraryInterface* metrics);
  ~TpmErrorUmaReporterImpl() override = default;

  // Not copyable or movable.
  TpmErrorUmaReporterImpl(const TpmErrorUmaReporterImpl&) = delete;
  TpmErrorUmaReporterImpl& operator=(const TpmErrorUmaReporterImpl&) = delete;
  TpmErrorUmaReporterImpl(TpmErrorUmaReporterImpl&&) = delete;
  TpmErrorUmaReporterImpl& operator=(TpmErrorUmaReporterImpl&&) = delete;

  void Report(const TpmErrorData& data) override;
  bool ReportTpm1CommandAndResponse(const TpmErrorData& data) override;
  bool ReportTpm2CommandAndResponse(const TpmErrorData& data) override;

 private:
  bool ReportCommandAndResponse(const std::string& metrics_prefix,
                                const TpmErrorData& data);

  MetricsLibrary default_metrics_;
  MetricsLibraryInterface* metrics_ = &default_metrics_;
};

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_TPM_ERROR_TPM_ERROR_UMA_REPORTER_IMPL_H_
