// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_COMMON_GSC_NVRAM_QUOTER_H_
#define ATTESTATION_COMMON_GSC_NVRAM_QUOTER_H_

#include "attestation/common/nvram_quoter.h"

#include <string>
#include <vector>

#include "attestation/common/tpm_utility.h"

namespace attestation {

class GscNvramQuoter : public NvramQuoter {
 public:
  explicit GscNvramQuoter(TpmUtility& tpm_utility);
  ~GscNvramQuoter() override = default;
  GscNvramQuoter(const GscNvramQuoter&) = delete;
  GscNvramQuoter(GscNvramQuoter&&) = delete;
  std::vector<NVRAMQuoteType> GetListForIdentity() const override;
  std::vector<NVRAMQuoteType> GetListForVtpmEkCertificate() const override;
  std::vector<NVRAMQuoteType> GetListForEnrollmentCertificate() const override;
  bool Certify(NVRAMQuoteType type,
               const std::string& signing_key_blob,
               Quote& quote) override;

 private:
  TpmUtility& tpm_utility_;
};

}  // namespace attestation

#endif  // ATTESTATION_COMMON_GSC_NVRAM_QUOTER_H_
