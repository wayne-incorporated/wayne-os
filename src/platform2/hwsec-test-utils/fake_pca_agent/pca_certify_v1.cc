// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/fake_pca_agent/pca_certify_v1.h"

#include <optional>
#include <string>
#include <utility>

#include <base/logging.h>
#include <base/memory/free_deleter.h>
#include <crypto/scoped_openssl_types.h>
#include <trousers/trousers.h>
#include <trousers/tss.h>

#include "hwsec-test-utils/common/openssl_utility.h"
#include "hwsec-test-utils/fake_pca_agent/issue_certificate.h"
#include "hwsec-test-utils/fake_pca_agent/tpm1_struct_utils.h"

namespace hwsec_test_utils {
namespace fake_pca_agent {

bool PcaCertifyV1::Preprocess() {
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

  certified_key_ = TpmPublicKeyToEVP(request_.certified_public_key(),
                                     &certified_key_digest_);
  if (!certified_key_) {
    LOG(ERROR) << __func__
               << ": Failed to parse certified key: " << GetOpenSSLError();
    return false;
  }
  return true;
}

bool PcaCertifyV1::Verify() {
  // Verify digest.
  std::optional<std::string> digest =
      ParseDigestFromTpmCertifyInfo(request_.certified_key_info());
  if (!digest) {
    LOG(ERROR) << __func__ << ": Failed to parse digest from the key info.";
    return false;
  }
  if (certified_key_digest_ != *digest) {
    LOG(ERROR) << __func__ << ": Mismatched public key digest.";
    return false;
  }

  // Verify signature.
  if (!EVPDigestVerify(identity_key_, EVP_sha1(), request_.certified_key_info(),
                       request_.certified_key_proof())) {
    LOG(ERROR) << __func__ << ": Failed to verify certified key proof.";
    return false;
  }
  return true;
}

bool PcaCertifyV1::Generate() {
  issued_certificate_der_ = IssueTestCertificateDer(certified_key_);
  if (!issued_certificate_der_) {
    LOG(ERROR) << __func__ << ": Failed to create certificate.";
    return false;
  }
  return true;
}

bool PcaCertifyV1::Write(
    attestation::AttestationCertificateResponse* response) {
  if (!issued_certificate_der_) {
    return false;
  }
  response->set_certified_key_credential(*issued_certificate_der_);
  return true;
}

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils
