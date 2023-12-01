// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_MOCK_RESPONSE_SERIALIZER_H_
#define TRUNKS_MOCK_RESPONSE_SERIALIZER_H_

#include "trunks/response_serializer.h"

#include <string>

#include <gmock/gmock.h>

#include "trunks/tpm_generated.h"

namespace trunks {

class MockResponseSerializer : public ResponseSerializer {
 public:
  ~MockResponseSerializer() override = default;

  MOCK_METHOD(void,
              SerializeHeaderOnlyResponse,
              (TPM_RC, std::string*),
              (override));
  MOCK_METHOD(void,
              SerializeResponseGetCapability,
              (TPMI_YES_NO, const TPMS_CAPABILITY_DATA&, std::string*),
              (override));
  MOCK_METHOD(void,
              SerializeResponseNvRead,
              (const TPM2B_MAX_NV_BUFFER&, std::string*),
              (override));
  MOCK_METHOD(void,
              SerializeResponseNvReadPublic,
              (const TPM2B_NV_PUBLIC&, const TPM2B_NAME&, std::string*),
              (override));
};
}  // namespace trunks

#endif  // TRUNKS_MOCK_RESPONSE_SERIALIZER_H_
