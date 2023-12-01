// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/common/tpm_utility_factory.h"

#include <base/logging.h>
#include <libhwsec-foundation/tpm/tpm_version.h>

#include "attestation/common/tpm_utility.h"

#if USE_TPM2
#include "attestation/common/tpm_utility_v2.h"
#endif

#if USE_TPM1
#include "attestation/common/tpm_utility_v1.h"
#endif

#include "attestation/common/tpm_utility_stub.h"

namespace attestation {

TpmUtility* TpmUtilityFactory::New() {
#if USE_TPM_DYNAMIC
  return new TpmUtilityStub();
#endif
  TPM_SELECT_BEGIN;
  TPM1_SECTION({ return new TpmUtilityV1(); });
  TPM2_SECTION({ return new TpmUtilityV2(); });
  OTHER_TPM_SECTION({ return new TpmUtilityStub(); });
  TPM_SELECT_END;
}

}  // namespace attestation
