// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FUZZED_SIGNING_H_
#define LIBHWSEC_FUZZED_SIGNING_H_

#include <fuzzer/FuzzedDataProvider.h>

#include "libhwsec/backend/signing.h"
#include "libhwsec/fuzzed/basic_objects.h"

namespace hwsec {

template <>
struct FuzzedObject<SigningOptions::PssParams> {
  SigningOptions::PssParams operator()(FuzzedDataProvider& provider) const {
    return SigningOptions::PssParams{
        .mgf1_algorithm = FuzzedObject<DigestAlgorithm>()(provider),
        .salt_length = FuzzedObject<size_t>()(provider),
    };
  }
};

template <>
struct FuzzedObject<SigningOptions> {
  SigningOptions operator()(FuzzedDataProvider& provider) const {
    using RsaPaddingScheme = SigningOptions::RsaPaddingScheme;
    using PssParams = SigningOptions::PssParams;
    return SigningOptions{
        .digest_algorithm = FuzzedObject<DigestAlgorithm>()(provider),
        .rsa_padding_scheme =
            FuzzedObject<std::optional<RsaPaddingScheme>>()(provider),
        .pss_params = FuzzedObject<std::optional<PssParams>>()(provider),
    };
  }
};

}  // namespace hwsec

#endif  // LIBHWSEC_FUZZED_SIGNING_H_
