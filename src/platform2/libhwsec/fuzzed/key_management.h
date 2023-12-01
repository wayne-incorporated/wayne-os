// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FUZZED_KEY_MANAGEMENT_H_
#define LIBHWSEC_FUZZED_KEY_MANAGEMENT_H_

#include <optional>
#include <type_traits>
#include <vector>

#include <brillo/secure_blob.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "libhwsec/backend/key_management.h"
#include "libhwsec/fuzzed/basic_objects.h"
#include "libhwsec/fuzzed/middleware.h"
#include "libhwsec/structures/key.h"

namespace hwsec {

template <>
struct FuzzedObject<Key> {
  Key operator()(FuzzedDataProvider& provider) const {
    return Key{
        .token = FuzzedObject<KeyToken>()(provider),
    };
  }
};

template <>
struct FuzzedObject<ScopedKey> {
  ScopedKey operator()(FuzzedDataProvider& provider) const {
    return ScopedKey(FuzzedObject<Key>()(provider),
                     FuzzedObject<MiddlewareDerivative>()(provider));
  }
};

template <>
struct FuzzedObject<KeyManagement::CreateKeyResult> {
  KeyManagement::CreateKeyResult operator()(
      FuzzedDataProvider& provider) const {
    return KeyManagement::CreateKeyResult{
        .key = FuzzedObject<ScopedKey>()(provider),
        .key_blob = FuzzedObject<brillo::Blob>()(provider),
    };
  }
};

template <>
struct FuzzedObject<RSAPublicInfo> {
  RSAPublicInfo operator()(FuzzedDataProvider& provider) const {
    return RSAPublicInfo{
        .exponent = FuzzedObject<brillo::Blob>()(provider),
        .modulus = FuzzedObject<brillo::Blob>()(provider),
    };
  }
};

template <>
struct FuzzedObject<ECCPublicInfo> {
  ECCPublicInfo operator()(FuzzedDataProvider& provider) const {
    return ECCPublicInfo{
        .nid = FuzzedObject<int>()(provider),
        .x_point = FuzzedObject<brillo::Blob>()(provider),
        .y_point = FuzzedObject<brillo::Blob>()(provider),
    };
  }
};

template <>
struct FuzzedObject<KeyManagement::CreateKeyOptions> {
  KeyManagement::CreateKeyOptions operator()(
      FuzzedDataProvider& provider) const {
    return KeyManagement::CreateKeyOptions{
        .allow_software_gen = FuzzedObject<bool>()(provider),
        .allow_decrypt = FuzzedObject<bool>()(provider),
        .allow_sign = FuzzedObject<bool>()(provider),
        .rsa_modulus_bits = FuzzedObject<std::optional<uint32_t>>()(provider),
        .rsa_exponent = FuzzedObject<std::optional<brillo::Blob>>()(provider),
        .ecc_nid = FuzzedObject<std::optional<uint32_t>>()(provider),
    };
  }
};

template <>
struct FuzzedObject<KeyManagement::LoadKeyOptions> {
  KeyManagement::LoadKeyOptions operator()(FuzzedDataProvider& provider) const {
    return KeyManagement::LoadKeyOptions{
        .auto_reload = FuzzedObject<bool>()(provider),
        .lazy_expiration_time = FuzzedObject<base::TimeDelta>()(provider),
    };
  }
};

}  // namespace hwsec

#endif  // LIBHWSEC_FUZZED_KEY_MANAGEMENT_H_
