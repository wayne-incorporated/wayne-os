// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_TEST_UTILS_WELL_KNOWN_KEY_PAIRS_WELL_KNOWN_KEY_PAIRS_H_
#define HWSEC_TEST_UTILS_WELL_KNOWN_KEY_PAIRS_WELL_KNOWN_KEY_PAIRS_H_

#include <crypto/scoped_openssl_types.h>

// In this file, we define the helper functions that create openssl key objects
// of the well-known key pairs. The function names explain themselves which PEM
// files they are associated with in this same directory.

namespace hwsec_test_utils {
namespace well_known_key_pairs {

crypto::ScopedEVP_PKEY GetCaEncryptionkey();

crypto::ScopedEVP_PKEY GetVaSigningkey();

crypto::ScopedEVP_PKEY GetVaEncryptionkey();

}  // namespace well_known_key_pairs
}  // namespace hwsec_test_utils

#endif  // HWSEC_TEST_UTILS_WELL_KNOWN_KEY_PAIRS_WELL_KNOWN_KEY_PAIRS_H_
