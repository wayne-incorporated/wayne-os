// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_STATIC_ANALYZER_H_
#define VTPM_BACKENDS_STATIC_ANALYZER_H_

#include <string>

#include <trunks/tpm_generated.h>

namespace vtpm {

// This type indicates the implication of a successful TPM command.
enum class OperationContextType {
  // No object is loaded, or unloaded/
  kNone,
  // Some object is loaded.
  kLoad,
  // Some object is unloaded.
  kUnload,
};

// This class defines a family of methods that judge the attributes of things,
// including but not lmited to a TPM command/response, w/ the knowldge on how
// TPM works.
class StaticAnalyzer {
 public:
  virtual ~StaticAnalyzer() = default;
  // Returns the number of handles that are required in a good `cc` command.
  virtual int GetCommandHandleCount(trunks::TPM_CC cc) = 0;
  // Returns the number of handles that are required in a good `cc` response.
  virtual int GetResponseHandleCount(trunks::TPM_CC cc) = 0;
  // Returns if the response code is `TPM_RC_SUCCESS` in `response. If the
  // response is ill-formed, also returns `false.
  // response is ill-formed or the res, also returns `false`.
  virtual bool IsSuccessfulResponse(const std::string& response) = 0;

  // Returns the corresponding `OperationContextType` of `cc`.
  virtual OperationContextType GetOperationContextType(trunks::TPM_CC cc) = 0;

  // Computes the name from a nv space public area `nv_public`. Returns an error
  // if marshal error occurs or the algorithm occurs.
  virtual trunks::TPM_RC ComputeNvName(const trunks::TPMS_NV_PUBLIC& nv_public,
                                       std::string& nv_name) = 0;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_STATIC_ANALYZER_H_
