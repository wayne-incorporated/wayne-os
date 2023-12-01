// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm2/version_attestation.h"

#include <string>

#include <libhwsec-foundation/status/status_chain_macros.h>

#include "libhwsec/error/tpm2_error.h"
#include "libhwsec/status.h"

using hwsec_foundation::status::MakeStatus;

namespace hwsec {

StatusOr<arc_attestation::CrOSVersionAttestationBlob>
VersionAttestationTpm2::AttestVersion(Key key,
                                      const std::string& cert,
                                      const brillo::Blob& challenge) {
  return MakeStatus<TPMError>("Unimplemented", TPMRetryAction::kNoRetry);
}

}  // namespace hwsec
