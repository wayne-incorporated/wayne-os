// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_COMMON_NULL_NVRAM_QUOTER_H_
#define ATTESTATION_COMMON_NULL_NVRAM_QUOTER_H_

#include "attestation/common/nvram_quoter.h"

#include <string>
#include <vector>

namespace attestation {

class NullNvramQuoter : public NvramQuoter {
 public:
  NullNvramQuoter() = default;
  ~NullNvramQuoter() override = default;
  NullNvramQuoter(const NullNvramQuoter&) = delete;
  NullNvramQuoter(NullNvramQuoter&&) = delete;
  std::vector<NVRAMQuoteType> GetListForIdentity() const override;
  std::vector<NVRAMQuoteType> GetListForVtpmEkCertificate() const override;
  std::vector<NVRAMQuoteType> GetListForEnrollmentCertificate() const override;
  bool Certify(NVRAMQuoteType type,
               const std::string& signing_key_blob,
               Quote& quote) override;
};

}  // namespace attestation

#endif  // ATTESTATION_COMMON_NULL_NVRAM_QUOTER_H_
