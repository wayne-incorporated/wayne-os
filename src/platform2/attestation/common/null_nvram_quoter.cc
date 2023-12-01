// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/common/null_nvram_quoter.h"

#include <string>
#include <vector>

#include <base/logging.h>

namespace attestation {

std::vector<NVRAMQuoteType> NullNvramQuoter::GetListForIdentity() const {
  return {};
}

std::vector<NVRAMQuoteType> NullNvramQuoter::GetListForVtpmEkCertificate()
    const {
  return {};
}

std::vector<NVRAMQuoteType> NullNvramQuoter::GetListForEnrollmentCertificate()
    const {
  return {};
}

bool NullNvramQuoter::Certify(NVRAMQuoteType, const std::string&, Quote&) {
  LOG(FATAL) << __func__ << ": null implemenetion called.";
  return false;
}

}  // namespace attestation
