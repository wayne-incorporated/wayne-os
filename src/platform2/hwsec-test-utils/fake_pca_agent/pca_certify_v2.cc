// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/fake_pca_agent/pca_certify_v2.h"

#include <memory>
#include <string>

#include <crypto/sha2.h>
#include <trunks/tpm_generated.h>

#include "hwsec-test-utils/common/openssl_utility.h"
#include "hwsec-test-utils/fake_pca_agent/issue_certificate.h"
#include "hwsec-test-utils/fake_pca_agent/tpm2_struct_utils.h"

#include <base/logging.h>

namespace hwsec_test_utils {
namespace fake_pca_agent {

bool PcaCertifyV2::Preprocess() {
  const unsigned char* asn1_ptr = reinterpret_cast<const unsigned char*>(
      request_.identity_credential().data());
  crypto::ScopedX509 x509(
      d2i_X509(nullptr, &asn1_ptr, request_.identity_credential().length()));
  if (!x509) {
    LOG(ERROR) << __func__
               << ": Failed to call d2i_X509: " << GetOpenSSLError();
    return false;
  }
  identity_key_.reset(X509_get_pubkey(x509.get()));
  if (!identity_key_) {
    LOG(ERROR) << __func__
               << ": Failed to call X509_get_pubkey: " << GetOpenSSLError();
    return false;
  }
  certified_key_ =
      TpmtPublicToEVP(request_.certified_public_key(), &certified_key_name_);
  if (!certified_key_) {
    LOG(ERROR) << __func__ << ": Failed to parse certified key.";
    return false;
  }

  return true;
}

bool PcaCertifyV2::Verify() {
  // Verify signature.
  if (!EVPDigestVerify(identity_key_, EVP_sha256(),
                       request_.certified_key_info(),
                       request_.certified_key_proof())) {
    LOG(ERROR) << __func__ << ": Failed to verify certified key proof.";
    return false;
  }

  // Verify digest in the key info.
  trunks::TPMS_ATTEST tpms_attest{};
  trunks::TPM_RC result;
  if ((result = trunks::Parse_TPMS_ATTEST(
           std::make_unique<std::string>(request_.certified_key_info()).get(),
           &tpms_attest, nullptr)) != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Failed to parse certified key info.";
    return false;
  }
  const std::string name_in_info(tpms_attest.attested.certify.name.name,
                                 tpms_attest.attested.certify.name.name +
                                     tpms_attest.attested.certify.name.size);
  if (certified_key_name_ != name_in_info) {
    LOG(ERROR) << __func__ << ": Mismatched key name.";
    return false;
  }

  return true;
}

bool PcaCertifyV2::Generate() {
  issued_certificate_der_ = IssueTestCertificateDer(certified_key_);
  if (!issued_certificate_der_) {
    LOG(ERROR) << __func__ << ": Failed to create certificate.";
    return false;
  }
  return true;
}

bool PcaCertifyV2::Write(
    attestation::AttestationCertificateResponse* response) {
  if (!issued_certificate_der_) {
    return false;
  }
  response->set_certified_key_credential(*issued_certificate_der_);
  return true;
}

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils
