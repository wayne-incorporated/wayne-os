// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_TEST_UTILS_FAKE_PCA_AGENT_KDF_H_
#define HWSEC_TEST_UTILS_FAKE_PCA_AGENT_KDF_H_

#include <optional>
#include <string>

namespace hwsec_test_utils {
namespace fake_pca_agent {

// TPM2.0 spec part 1, 11.4.10.3. The bit length is hardcoded to 256 and the
// digest algorithm to SHA-256 considering the limited use-cases in practice.
std::string KDFe(const std::string& z,
                 const std::string& use,
                 const std::string& party_u_info,
                 const std::string& party_v_info);

// TPM2.0 spec part 1, 11.4.10.2. The bit length of 128 and 256 are supported
// and the digest algorithm is hardcoded to SHA-256 considering the limited
// use-cases in practice.
std::optional<std::string> KDFa(const std::string& key,
                                const std::string& label,
                                const std::string& context_u,
                                const std::string& context_v,
                                int bits);

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils

#endif  // HWSEC_TEST_UTILS_FAKE_PCA_AGENT_KDF_H_
