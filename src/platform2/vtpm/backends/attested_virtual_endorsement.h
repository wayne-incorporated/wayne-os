// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_ATTESTED_VIRTUAL_ENDORSEMENT_H_
#define VTPM_BACKENDS_ATTESTED_VIRTUAL_ENDORSEMENT_H_

#include "vtpm/backends/virtual_endorsement.h"

#include <string>

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <attestation/proto_bindings/interface.pb.h>
#include <brillo/errors/error.h>
#include <trunks/tpm_generated.h>

// Requires proto_bindings `attestation`.
#include <attestation-client/attestation/dbus-proxies.h>

namespace vtpm {

// This implementation of `VirtualEndorsement` uses attestation service to get a
// virtual endorsment key certified by ChromeOS PCA server.
class AttestedVirtualEndorsement : public VirtualEndorsement {
  using AttestationProxyInterface = org::chromium::AttestationProxyInterface;

 public:
  explicit AttestedVirtualEndorsement(
      AttestationProxyInterface* attestation_proxy);
  ~AttestedVirtualEndorsement() override = default;

  trunks::TPM_RC Create() override;

  std::string GetEndorsementKey() override;

  std::string GetEndorsementCertificate() override;

 private:
  AttestationProxyInterface* const attestation_proxy_;
  // Once `Create()` is called, the result is cached in `blob_` and
  // `certificate_` respectively.
  std::string blob_;
  std::string certificate_;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_ATTESTED_VIRTUAL_ENDORSEMENT_H_
