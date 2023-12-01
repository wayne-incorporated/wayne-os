// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/vek_cert.h"

#include <string>

#include <trunks/tpm_generated.h>

namespace vtpm {

VekCert::VekCert(VirtualEndorsement* e) : endorsement_(e) {}

trunks::TPM_RC VekCert::Get(std::string& blob) {
  trunks::TPM_RC rc = endorsement_->Create();
  if (rc) {
    return rc;
  }
  blob = endorsement_->GetEndorsementCertificate();
  return trunks::TPM_RC_SUCCESS;
}

}  // namespace vtpm
