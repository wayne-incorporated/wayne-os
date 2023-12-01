// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/vek.h"

#include <string>

#include <base/check.h>
#include <trunks/tpm_generated.h>

namespace vtpm {

Vek::Vek(VirtualEndorsement* e) : endorsement_(e) {
  CHECK(e);
}

trunks::TPM_RC Vek::Get(std::string& blob) {
  trunks::TPM_RC rc = endorsement_->Create();
  if (rc) {
    return rc;
  }
  blob = endorsement_->GetEndorsementKey();
  return trunks::TPM_RC_SUCCESS;
}

}  // namespace vtpm
