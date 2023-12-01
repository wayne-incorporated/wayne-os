// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_TEST_UTILS_FAKE_PCA_AGENT_PCA_CERTIFY_V2_H_
#define HWSEC_TEST_UTILS_FAKE_PCA_AGENT_PCA_CERTIFY_V2_H_

#include "hwsec-test-utils/fake_pca_agent/pca_base.h"

#include <optional>
#include <string>

#include <attestation/proto_bindings/attestation_ca.pb.h>

namespace hwsec_test_utils {
namespace fake_pca_agent {

// Certification implementation for TPM2.0.
class PcaCertifyV2
    : public PcaBase<attestation::AttestationCertificateRequest,
                     attestation::AttestationCertificateResponse> {
 public:
  PcaCertifyV2() = delete;
  // Expose base's constructor so we can initialize the request.
  using PcaBase::PcaBase;
  ~PcaCertifyV2() override = default;

  // Not copyable or movable.
  PcaCertifyV2(const PcaCertifyV2&) = delete;
  PcaCertifyV2& operator=(const PcaCertifyV2&) = delete;
  PcaCertifyV2(PcaCertifyV2&&) = delete;
  PcaCertifyV2& operator=(PcaCertifyV2&&) = delete;

  bool Preprocess() override;
  bool Verify() override;
  bool Generate() override;
  bool Write(attestation::AttestationCertificateResponse* response) override;

 private:
  crypto::ScopedEVP_PKEY identity_key_;
  crypto::ScopedEVP_PKEY certified_key_;
  std::string certified_key_name_;
  std::optional<std::string> issued_certificate_der_;
};

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils

#endif  // HWSEC_TEST_UTILS_FAKE_PCA_AGENT_PCA_CERTIFY_V2_H_
