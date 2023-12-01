// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/tpm_error/tpm_error_uma_report.h"

#include "libhwsec-foundation/tpm_error/tpm_error_data.h"
#include "libhwsec-foundation/tpm_error/tpm_error_uma_reporter_impl.h"

extern "C" int ReportTpm1CommandAndResponse(const struct TpmErrorData* data) {
  hwsec_foundation::TpmErrorUmaReporterImpl reporter;
  return reporter.ReportTpm1CommandAndResponse(*data);
}
