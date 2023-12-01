// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/common/nvram_quoter_factory.h"

#if USE_CR50_ONBOARD || USE_TI50_ONBOARD
#include "attestation/common/gsc_nvram_quoter.h"
#else
#include "attestation/common/null_nvram_quoter.h"
#endif

namespace attestation {

// static
NvramQuoter* NvramQuoterFactory::New(TpmUtility& tpm_utility) {
#if USE_CR50_ONBOARD || USE_TI50_ONBOARD
  return new GscNvramQuoter(tpm_utility);
#else
  return new NullNvramQuoter();
#endif
}

}  // namespace attestation
