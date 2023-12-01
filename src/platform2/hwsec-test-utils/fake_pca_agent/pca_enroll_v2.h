// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_TEST_UTILS_FAKE_PCA_AGENT_PCA_ENROLL_V2_H_
#define HWSEC_TEST_UTILS_FAKE_PCA_AGENT_PCA_ENROLL_V2_H_

#include "hwsec-test-utils/fake_pca_agent/pca_base.h"

#include <optional>
#include <string>

#include <attestation/proto_bindings/attestation_ca.pb.h>

namespace hwsec_test_utils {
namespace fake_pca_agent {

// Enrollment implementation for TPM2.0.
class PcaEnrollV2 : public PcaBase<attestation::AttestationEnrollmentRequest,
                                   attestation::AttestationEnrollmentResponse> {
 public:
  PcaEnrollV2() = delete;
  // Expose base's constructor so we can initialize the request.
  using PcaBase::PcaBase;
  ~PcaEnrollV2() override = default;

  // Not copyable or movable.
  PcaEnrollV2(const PcaEnrollV2&) = delete;
  PcaEnrollV2& operator=(const PcaEnrollV2&) = delete;
  PcaEnrollV2(PcaEnrollV2&&) = delete;
  PcaEnrollV2& operator=(PcaEnrollV2&&) = delete;

  bool Preprocess() override;
  bool Verify() override;
  bool Generate() override;
  bool Write(attestation::AttestationEnrollmentResponse* response) override;

 private:
  crypto::ScopedEVP_PKEY endorsement_key_;
  crypto::ScopedEVP_PKEY identity_key_;
  std::string identity_key_name_;
  std::optional<attestation::EncryptedIdentityCredential>
      encrypted_identity_credential_;
};

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils

#endif  // HWSEC_TEST_UTILS_FAKE_PCA_AGENT_PCA_ENROLL_V2_H_
