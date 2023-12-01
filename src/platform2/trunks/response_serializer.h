// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_RESPONSE_SERIALIZER_H_
#define TRUNKS_RESPONSE_SERIALIZER_H_

#include <string>

#include "trunks/tpm_generated.h"
#include "trunks/trunks_export.h"

namespace trunks {

// A class that serialize TPM responses.
class TRUNKS_EXPORT ResponseSerializer {
 public:
  virtual ~ResponseSerializer() = default;

  // Serializes `rc` into a TPM command header.
  virtual void SerializeHeaderOnlyResponse(TPM_RC rc,
                                           std::string* response) = 0;

  // Serializes the response for `TPM2_GetCapability`.
  virtual void SerializeResponseGetCapability(
      TPMI_YES_NO has_more,
      const TPMS_CAPABILITY_DATA& cap_data,
      std::string* response) = 0;

  // Serializes the response for `TPM2_NV_Read`.
  virtual void SerializeResponseNvRead(const TPM2B_MAX_NV_BUFFER& data,
                                       std::string* response) = 0;

  // Serializes the response for `TPM2_NV_ReadPublic`.
  virtual void SerializeResponseNvReadPublic(const TPM2B_NV_PUBLIC& nv_public,
                                             const TPM2B_NAME& nv_name,
                                             std::string* response) = 0;
};
}  // namespace trunks

#endif  // TRUNKS_RESPONSE_SERIALIZER_H_
