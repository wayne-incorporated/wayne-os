// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_TEST_UTILS_FAKE_PCA_AGENT_PCA_ENROLL_V1_H_
#define HWSEC_TEST_UTILS_FAKE_PCA_AGENT_PCA_ENROLL_V1_H_

#include "hwsec-test-utils/fake_pca_agent/pca_base.h"

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <crypto/scoped_openssl_types.h>

#include <optional>

namespace hwsec_test_utils {
namespace fake_pca_agent {

// Enrollment implementation for TPM1.2.
class PcaEnrollV1 : public PcaBase<attestation::AttestationEnrollmentRequest,
                                   attestation::AttestationEnrollmentResponse> {
 public:
  PcaEnrollV1() = delete;
  // Expose base's constructor so we can initialize the request.
  using PcaBase::PcaBase;
  ~PcaEnrollV1() override = default;

  // Not copyable or movable.
  PcaEnrollV1(const PcaEnrollV1&) = delete;
  PcaEnrollV1& operator=(const PcaEnrollV1&) = delete;
  PcaEnrollV1(PcaEnrollV1&&) = delete;
  PcaEnrollV1& operator=(PcaEnrollV1&&) = delete;

  bool Preprocess() override;
  bool Verify() override;
  bool Generate() override;
  bool Write(attestation::AttestationEnrollmentResponse* response) override;

 private:
  crypto::ScopedEVP_PKEY endorsement_key_;
  crypto::ScopedEVP_PKEY identity_key_;
  std::optional<attestation::EncryptedIdentityCredential>
      encrypted_identity_credential_;
};

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils

#endif  // HWSEC_TEST_UTILS_FAKE_PCA_AGENT_PCA_ENROLL_V1_H_
