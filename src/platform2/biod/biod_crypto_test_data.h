// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_BIOD_CRYPTO_TEST_DATA_H_
#define BIOD_BIOD_CRYPTO_TEST_DATA_H_

#include <cstdint>
#include <vector>

#include <brillo/secure_blob.h>

namespace biod {
namespace crypto_test_data {

inline constexpr char kUserID[] = "0123456789";
inline const brillo::SecureVector kFakePositiveMatchSecret1 = {0x00, 0x01,
                                                               0x02};
inline const brillo::SecureVector kFakePositiveMatchSecret2 = {0xcc, 0xdd, 0xee,
                                                               0xff};
// Validation value corresponding to kFakePositiveMatchSecret1 and kUserID.
inline const std::vector<uint8_t> kFakeValidationValue1 = {
    0x90, 0xea, 0xfb, 0x75, 0xee, 0x37, 0xeb, 0xb1, 0xb5, 0xe7, 0x81,
    0x47, 0xac, 0xdd, 0xff, 0xbe, 0x20, 0x59, 0x25, 0x24, 0x82, 0xe0,
    0x05, 0xdd, 0x95, 0x09, 0x8e, 0x5a, 0xdc, 0xcc, 0x12, 0x9f,
};
// Validation value corresponding to kFakePositiveMatchSecret2 and kUserID.
inline const std::vector<uint8_t> kFakeValidationValue2 = {
    0xde, 0xe9, 0x4d, 0xbd, 0xbe, 0x63, 0x8b, 0x9e, 0xc9, 0x25, 0x27,
    0xf1, 0xf6, 0x86, 0x6f, 0xb3, 0x31, 0xf6, 0xb6, 0x52, 0x99, 0x66,
    0x89, 0x88, 0x73, 0x0a, 0xd4, 0x0b, 0xd2, 0x34, 0x7b, 0x71,
};

}  // namespace crypto_test_data
}  // namespace biod

#endif  // BIOD_BIOD_CRYPTO_TEST_DATA_H_
