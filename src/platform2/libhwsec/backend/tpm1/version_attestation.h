// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_VERSION_ATTESTATION_H_
#define LIBHWSEC_BACKEND_TPM1_VERSION_ATTESTATION_H_

#include <string>

#include "libhwsec/backend/version_attestation.h"
#include "libhwsec/status.h"

namespace hwsec {

// Note that version attestation is unavailable for TPM 1.2 devices and this
// class is only here to return that it's unsupported.
class VersionAttestationTpm1 : public VersionAttestation {
 public:
  VersionAttestationTpm1() {}

  StatusOr<arc_attestation::CrOSVersionAttestationBlob> AttestVersion(
      Key key, const std::string& cert, const brillo::Blob& challenge) override;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_VERSION_ATTESTATION_H_
