// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/attested_virtual_endorsement.h"

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <attestation/proto_bindings/interface.pb.h>
#include <brillo/errors/error.h>

// Requires proto_bindings `attestation`.
#include <attestation-client/attestation/dbus-proxies.h>

namespace vtpm {

namespace {

using org::chromium::AttestationProxyInterface;

constexpr char kVtpmEkLabel[] = "vtpm-ek";
constexpr base::TimeDelta kAttestationFlowTimeout = base::Minutes(5);
}  // namespace

AttestedVirtualEndorsement::AttestedVirtualEndorsement(
    AttestationProxyInterface* attestation_proxy)
    : attestation_proxy_(attestation_proxy) {
  CHECK(attestation_proxy_);
}

trunks::TPM_RC AttestedVirtualEndorsement::Create() {
  attestation::GetCertificateRequest request;
  request.set_key_label(kVtpmEkLabel);
  request.set_certificate_profile(attestation::ENTERPRISE_VTPM_EK_CERTIFICATE);
  request.set_username("");
  request.set_key_type(attestation::KEY_TYPE_ECC);
  // Attestation-enroll transparently.
  request.set_shall_trigger_enrollment(true);

  attestation::GetCertificateReply reply;

  // D-Buse communication issue; treat it as a TPM failure (assuming the timeout
  // is generous enough).
  brillo::ErrorPtr error_ptr;
  if (!attestation_proxy_->GetCertificate(
          request, &reply, &error_ptr,
          kAttestationFlowTimeout.InMilliseconds())) {
    LOG(ERROR) << __func__
               << "D-Bus error: " << error_ptr->GetMessage().c_str();
    return trunks::TPM_RC_FAILURE;
  }
  if (reply.status() != ::attestation::STATUS_SUCCESS) {
    LOG(ERROR) << __func__
               << "Failed to get certificate; status: " << reply.status();
    return trunks::TPM_RC_FAILURE;
  }
  // Extract the key, blob, and the certificate.
  blob_ = reply.key_blob();
  certificate_ = reply.certified_key_credential();
  return trunks::TPM_RC_SUCCESS;
}

std::string AttestedVirtualEndorsement::GetEndorsementKey() {
  return blob_;
}

std::string AttestedVirtualEndorsement::GetEndorsementCertificate() {
  return certificate_;
}

}  // namespace vtpm
