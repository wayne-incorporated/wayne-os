// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_REAL_STATIC_ANALYZER_H_
#define VTPM_BACKENDS_REAL_STATIC_ANALYZER_H_

#include "vtpm/backends/static_analyzer.h"

#include <string>

#include <trunks/tpm_generated.h>

namespace vtpm {

// This implements `StaticAnalyzer` with knowledge on how real TPM2.0 works.
class RealStaticAnalyzer : public StaticAnalyzer {
 public:
  ~RealStaticAnalyzer() override = default;
  int GetCommandHandleCount(trunks::TPM_CC cc) override;
  int GetResponseHandleCount(trunks::TPM_CC cc) override;
  bool IsSuccessfulResponse(const std::string& response) override;
  OperationContextType GetOperationContextType(trunks::TPM_CC cc) override;
  trunks::TPM_RC ComputeNvName(const trunks::TPMS_NV_PUBLIC& nv_public,
                               std::string& nv_name) override;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_REAL_STATIC_ANALYZER_H_
