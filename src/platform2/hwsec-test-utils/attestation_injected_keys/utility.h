// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_TEST_UTILS_ATTESTATION_INJECTED_KEYS_UTILITY_H_
#define HWSEC_TEST_UTILS_ATTESTATION_INJECTED_KEYS_UTILITY_H_

#include <attestation/proto_bindings/google_key.pb.h>

namespace hwsec_test_utils {

attestation::DefaultGoogleRsaPublicKeySet GenerateAttestationGoogleKeySet();

}  // namespace hwsec_test_utils

#endif  // HWSEC_TEST_UTILS_ATTESTATION_INJECTED_KEYS_UTILITY_H_
