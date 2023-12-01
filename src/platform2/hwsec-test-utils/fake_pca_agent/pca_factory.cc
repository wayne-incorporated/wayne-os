// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/fake_pca_agent/pca_factory.h"

#include <memory>
#include <utility>

#include <libhwsec-foundation/tpm/tpm_version.h>

#if USE_TPM2
#include "hwsec-test-utils/fake_pca_agent/pca_certify_v2.h"
#include "hwsec-test-utils/fake_pca_agent/pca_enroll_v2.h"
#endif

#if USE_TPM1
#include "hwsec-test-utils/fake_pca_agent/pca_certify_v1.h"
#include "hwsec-test-utils/fake_pca_agent/pca_enroll_v1.h"
#endif

namespace hwsec_test_utils {
namespace fake_pca_agent {

std::unique_ptr<PcaBase<attestation::AttestationEnrollmentRequest,
                        attestation::AttestationEnrollmentResponse>>
CreatePcaEnroll(attestation::AttestationEnrollmentRequest request) {
  TPM_SELECT_BEGIN;
  TPM2_SECTION({ return std::make_unique<PcaEnrollV2>(std::move(request)); });
  TPM1_SECTION({ return std::make_unique<PcaEnrollV1>(std::move(request)); });
  OTHER_TPM_SECTION();
  TPM_SELECT_END;
  return nullptr;
}

std::unique_ptr<PcaBase<attestation::AttestationCertificateRequest,
                        attestation::AttestationCertificateResponse>>
CreatePcaCertify(attestation::AttestationCertificateRequest request) {
  TPM_SELECT_BEGIN;
  TPM2_SECTION({ return std::make_unique<PcaCertifyV2>(std::move(request)); });
  TPM1_SECTION({ return std::make_unique<PcaCertifyV1>(std::move(request)); });
  OTHER_TPM_SECTION();
  TPM_SELECT_END;
  return nullptr;
}

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils
