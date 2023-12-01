// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_COMMON_NVRAM_QUOTER_H_
#define ATTESTATION_COMMON_NVRAM_QUOTER_H_

#include <string>
#include <vector>

#include <attestation/proto_bindings/attestation_ca.pb.h>

namespace attestation {

class NvramQuoter {
 public:
  virtual ~NvramQuoter() = default;
  virtual std::vector<NVRAMQuoteType> GetListForIdentity() const = 0;
  virtual std::vector<NVRAMQuoteType> GetListForVtpmEkCertificate() const = 0;
  virtual std::vector<NVRAMQuoteType> GetListForEnrollmentCertificate()
      const = 0;
  virtual bool Certify(NVRAMQuoteType type,
                       const std::string& signing_key_blob,
                       Quote& quote) = 0;
};

}  // namespace attestation

#endif  // ATTESTATION_COMMON_NVRAM_QUOTER_H_
