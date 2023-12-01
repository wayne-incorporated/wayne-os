// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_REAL_RESPONSE_SERIALIZER_H_
#define TRUNKS_REAL_RESPONSE_SERIALIZER_H_

#include "trunks/response_serializer.h"

#include <string>

#include "trunks/tpm_generated.h"
#include "trunks/trunks_export.h"

namespace trunks {

// An implementation that serialize the real (i.e., defined by TPM2.0 spec) TPM
// responses.
class TRUNKS_EXPORT RealResponseSerializer : public ResponseSerializer {
 public:
  ~RealResponseSerializer() override = default;

  void SerializeHeaderOnlyResponse(TPM_RC rc, std::string* response) override;
  void SerializeResponseGetCapability(TPMI_YES_NO has_more,
                                      const TPMS_CAPABILITY_DATA& cap_data,
                                      std::string* response) override;
  void SerializeResponseNvRead(const TPM2B_MAX_NV_BUFFER& data,
                               std::string* response) override;
  void SerializeResponseNvReadPublic(const TPM2B_NV_PUBLIC& nv_public,
                                     const TPM2B_NAME& nv_name,
                                     std::string* response) override;
};
}  // namespace trunks

#endif  // TRUNKS_REAL_RESPONSE_SERIALIZER_H_
