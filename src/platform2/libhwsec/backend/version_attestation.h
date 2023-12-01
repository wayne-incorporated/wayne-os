// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_VERSION_ATTESTATION_H_
#define LIBHWSEC_BACKEND_VERSION_ATTESTATION_H_

#include <optional>
#include <string>

#include <brillo/secure_blob.h>

#include "libarc_attestation/proto_bindings/arc_attestation_blob.pb.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"

namespace hwsec {

class VersionAttestation {
 public:
  // This tries to produce a version attestation with the given |key|. The
  // |cert| is the x509 PEM encoded certificate chain for the |key|. |challenge|
  // is the challenge to include within the various quotations. |key| must be a
  // restricted signing key.
  virtual StatusOr<arc_attestation::CrOSVersionAttestationBlob> AttestVersion(
      Key key, const std::string& cert, const brillo::Blob& challenge) = 0;

 protected:
  VersionAttestation() = default;
  ~VersionAttestation() = default;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_VERSION_ATTESTATION_H_
