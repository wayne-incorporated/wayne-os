// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_COMMON_NVRAM_QUOTER_FACTORY_H_
#define ATTESTATION_COMMON_NVRAM_QUOTER_FACTORY_H_

#include "attestation/common/nvram_quoter.h"

#include "attestation/common/tpm_utility.h"

namespace attestation {

class NvramQuoterFactory {
 public:
  static NvramQuoter* New(TpmUtility& tpm_utility);
};

}  // namespace attestation

#endif  // ATTESTATION_COMMON_NVRAM_QUOTER_FACTORY_H_
