// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/real_static_analyzer.h"

#include <string>

#include <base/logging.h>
#include <crypto/sha2.h>
#include <trunks/command_parser.h>
#include <trunks/tpm_generated.h>

namespace vtpm {

int RealStaticAnalyzer::GetCommandHandleCount(trunks::TPM_CC cc) {
  // The handle to be flushed is a parameter instead of a handle field.
  if (cc == trunks::TPM_CC_FlushContext) {
    return 1;
  }
  return trunks::GetNumberOfRequestHandles(cc);
}

int RealStaticAnalyzer::GetResponseHandleCount(trunks::TPM_CC cc) {
  return trunks::GetNumberOfResponseHandles(cc);
}

bool RealStaticAnalyzer::IsSuccessfulResponse(const std::string& response) {
  std::string serialized_rc = response.substr(
      trunks::kHeaderSize - sizeof(trunks::TPM_RC), sizeof(trunks::TPM_RC));
  trunks::TPM_RC rc;
  if (trunks::Parse_TPM_RC(&serialized_rc, &rc, nullptr)) {
    return false;
  }
  return rc == trunks::TPM_RC_SUCCESS;
}

OperationContextType RealStaticAnalyzer::GetOperationContextType(
    trunks::TPM_CC cc) {
  if (cc == trunks::TPM_CC_Load) {
    return OperationContextType::kLoad;
  }
  if (cc == trunks::TPM_CC_FlushContext) {
    return OperationContextType::kUnload;
  }
  return OperationContextType::kNone;
}

trunks::TPM_RC RealStaticAnalyzer::ComputeNvName(
    const trunks::TPMS_NV_PUBLIC& nv_public, std::string& nv_name) {
  if (nv_public.name_alg != trunks::TPM_ALG_SHA256) {
    return trunks::TPM_RC_HASH;
  }
  std::string serialized_public_area;
  trunks::TPM_RC rc =
      trunks::Serialize_TPMS_NV_PUBLIC(nv_public, &serialized_public_area);
  if (rc) {
    return rc;
  }
  std::string serialized_name_alg;
  trunks::Serialize_TPM_ALG_ID(nv_public.name_alg, &serialized_name_alg);
  // Hardcode to sha256, the only supported name algorithm.
  nv_name =
      serialized_name_alg + crypto::SHA256HashString(serialized_public_area);
  return trunks::TPM_RC_SUCCESS;
}

}  // namespace vtpm
