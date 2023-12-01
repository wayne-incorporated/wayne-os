// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_TEST_UTILS_FAKE_PCA_AGENT_PCA_FACTORY_H_
#define HWSEC_TEST_UTILS_FAKE_PCA_AGENT_PCA_FACTORY_H_

#include <memory>

#include <attestation/proto_bindings/attestation_ca.pb.h>

#include "hwsec-test-utils/fake_pca_agent/pca_base.h"

// This file provides a set of APIs that creates a enrollment/certification
// subclass of |PcaBase| depending on the version.

namespace hwsec_test_utils {
namespace fake_pca_agent {

std::unique_ptr<PcaBase<attestation::AttestationEnrollmentRequest,
                        attestation::AttestationEnrollmentResponse>>
CreatePcaEnroll(attestation::AttestationEnrollmentRequest request);

std::unique_ptr<PcaBase<attestation::AttestationCertificateRequest,
                        attestation::AttestationCertificateResponse>>
CreatePcaCertify(attestation::AttestationCertificateRequest request);

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils

#endif  // HWSEC_TEST_UTILS_FAKE_PCA_AGENT_PCA_FACTORY_H_
