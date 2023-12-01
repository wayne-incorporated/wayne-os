// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_MOCK_STATIC_ANALYZER_H_
#define VTPM_BACKENDS_MOCK_STATIC_ANALYZER_H_

#include "vtpm/backends/static_analyzer.h"

#include <string>

#include <gmock/gmock.h>
#include <trunks/tpm_generated.h>

namespace vtpm {

class MockStaticAnalyzer : public StaticAnalyzer {
 public:
  ~MockStaticAnalyzer() override = default;
  MOCK_METHOD(int, GetCommandHandleCount, (trunks::TPM_CC cc), (override));
  MOCK_METHOD(int, GetResponseHandleCount, (trunks::TPM_CC cc), (override));
  MOCK_METHOD(bool, IsSuccessfulResponse, (const std::string&), (override));
  MOCK_METHOD(OperationContextType,
              GetOperationContextType,
              (trunks::TPM_CC),
              (override));
  MOCK_METHOD(trunks::TPM_RC,
              ComputeNvName,
              (const trunks::TPMS_NV_PUBLIC&, std::string&),
              (override));
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_MOCK_STATIC_ANALYZER_H_
