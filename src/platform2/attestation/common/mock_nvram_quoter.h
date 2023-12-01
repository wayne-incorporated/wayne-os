// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_COMMON_MOCK_NVRAM_QUOTER_H_
#define ATTESTATION_COMMON_MOCK_NVRAM_QUOTER_H_

#include "attestation/common/nvram_quoter.h"

#include <string>
#include <vector>

#include <gmock/gmock.h>

namespace attestation {

class MockNvramQuoter : public NvramQuoter {
 public:
  MockNvramQuoter() = default;
  ~MockNvramQuoter() override = default;

  MOCK_METHOD(std::vector<NVRAMQuoteType>,
              GetListForIdentity,
              (),
              (const, override));
  MOCK_METHOD(std::vector<NVRAMQuoteType>,
              GetListForEnrollmentCertificate,
              (),
              (const, override));
  MOCK_METHOD(std::vector<NVRAMQuoteType>,
              GetListForVtpmEkCertificate,
              (),
              (const, override));
  MOCK_METHOD(bool,
              Certify,
              (NVRAMQuoteType, const std::string&, Quote&),
              (override));
};

}  // namespace attestation

#endif  // ATTESTATION_COMMON_MOCK_NVRAM_QUOTER_H_
