// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_softclear_utils/tpm.h"

#include <libhwsec-foundation/tpm/tpm_version.h>

#if USE_TPM2
#include "tpm_softclear_utils/tpm2_impl.h"
#endif

#if USE_TPM1
#include "tpm_softclear_utils/tpm_impl.h"
#endif

namespace tpm_softclear_utils {

Tpm* Tpm::Create() {
  TPM_SELECT_BEGIN;
  TPM1_SECTION({ return new TpmImpl(); });
  TPM2_SECTION({ return new Tpm2Impl(); });
  OTHER_TPM_SECTION();
  TPM_SELECT_END;
  return nullptr;
}

}  // namespace tpm_softclear_utils
