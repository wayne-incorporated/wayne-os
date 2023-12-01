// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/logging.h>
#include <libhwsec-foundation/tpm/tpm_version.h>

#include "hwsec-test-utils/ownership_id/ownership_id_factory.h"

#if USE_TPM1
#include "hwsec-test-utils/ownership_id/ownership_id_tpm1.h"
#endif

#if USE_TPM2
#include "hwsec-test-utils/ownership_id/ownership_id_tpm2.h"
#endif

namespace hwsec_test_utils {

std::unique_ptr<OwnershipId> GetOwnershipId() {
  TPM_SELECT_BEGIN;
  TPM1_SECTION({ return std::make_unique<OwnershipIdTpm1>(); });
  TPM2_SECTION({ return std::make_unique<OwnershipIdTpm2>(); });
  OTHER_TPM_SECTION({
    LOG(ERROR) << "No TPM on the device";
    return nullptr;
  });
  TPM_SELECT_END;
}

}  // namespace hwsec_test_utils
