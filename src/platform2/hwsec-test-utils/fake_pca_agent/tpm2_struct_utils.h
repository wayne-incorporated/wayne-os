// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_TEST_UTILS_FAKE_PCA_AGENT_TPM2_STRUCT_UTILS_H_
#define HWSEC_TEST_UTILS_FAKE_PCA_AGENT_TPM2_STRUCT_UTILS_H_

#if !USE_TPM2
#error "This file is used for TPM2.0 only"
#endif

#include <string>

#include <crypto/scoped_openssl_types.h>

namespace hwsec_test_utils {
namespace fake_pca_agent {

// Parse |serialized| into trunks::TPMT_PUBLIC and convert it to EVP_PKEY.
// Note that currently this function only supports ECC key type. If |name| !=
// nullptr, calculates the public key's name and assigns the result to |name|.
// Currently only SHA256 for name algorithm is supported.
crypto::ScopedEVP_PKEY TpmtPublicToEVP(std::string serialized,
                                       std::string* name);

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils

#endif  // HWSEC_TEST_UTILS_FAKE_PCA_AGENT_TPM2_STRUCT_UTILS_H_
