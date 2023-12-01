// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FUZZED_SIGNATURE_SEALING_H_
#define LIBHWSEC_FUZZED_SIGNATURE_SEALING_H_

#include <optional>
#include <type_traits>
#include <vector>

#include <brillo/secure_blob.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "libhwsec/backend/signature_sealing.h"
#include "libhwsec/fuzzed/basic_objects.h"
#include "libhwsec/structures/signature_sealed_data.h"

namespace hwsec {

template <>
struct FuzzedObject<SignatureSealing::ChallengeResult> {
  SignatureSealing::ChallengeResult operator()(
      FuzzedDataProvider& provider) const {
    return SignatureSealing::ChallengeResult{
        .challenge_id = FuzzedObject<SignatureSealing::ChallengeID>()(provider),
        .algorithm = FuzzedObject<SignatureSealing::Algorithm>()(provider),
        .challenge = FuzzedObject<brillo::Blob>()(provider),
    };
  }
};

template <>
struct FuzzedObject<Tpm2PolicyDigest> {
  Tpm2PolicyDigest operator()(FuzzedDataProvider& provider) const {
    return Tpm2PolicyDigest{
        .digest = FuzzedObject<brillo::Blob>()(provider),
    };
  }
};

template <>
struct FuzzedObject<Tpm2PolicySignedData> {
  Tpm2PolicySignedData operator()(FuzzedDataProvider& provider) const {
    return Tpm2PolicySignedData{
        .public_key_spki_der = FuzzedObject<brillo::Blob>()(provider),
        .srk_wrapped_secret = FuzzedObject<brillo::Blob>()(provider),
        .scheme = FuzzedObject<std::optional<int32_t>>()(provider),
        .hash_alg = FuzzedObject<std::optional<int32_t>>()(provider),
        .pcr_policy_digests =
            FuzzedObject<std::vector<Tpm2PolicyDigest>>()(provider),
    };
  }
};

template <>
struct FuzzedObject<Tpm12PcrValue> {
  Tpm12PcrValue operator()(FuzzedDataProvider& provider) const {
    return Tpm12PcrValue{
        .pcr_index = FuzzedObject<std::optional<uint32_t>>()(provider),
        .pcr_value = FuzzedObject<brillo::Blob>()(provider),
    };
  }
};

template <>
struct FuzzedObject<Tpm12PcrBoundItem> {
  Tpm12PcrBoundItem operator()(FuzzedDataProvider& provider) const {
    return Tpm12PcrBoundItem{
        .pcr_values = FuzzedObject<std::vector<Tpm12PcrValue>>()(provider),
        .bound_secret = FuzzedObject<brillo::Blob>()(provider),
    };
  }
};

template <>
struct FuzzedObject<Tpm12CertifiedMigratableKeyData> {
  Tpm12CertifiedMigratableKeyData operator()(
      FuzzedDataProvider& provider) const {
    return Tpm12CertifiedMigratableKeyData{
        .public_key_spki_der = FuzzedObject<brillo::Blob>()(provider),
        .srk_wrapped_cmk = FuzzedObject<brillo::Blob>()(provider),
        .cmk_pubkey = FuzzedObject<brillo::Blob>()(provider),
        .cmk_wrapped_auth_data = FuzzedObject<brillo::Blob>()(provider),
        .pcr_bound_items =
            FuzzedObject<std::vector<Tpm12PcrBoundItem>>()(provider),
    };
  }
};

}  // namespace hwsec

#endif  // LIBHWSEC_FUZZED_SIGNATURE_SEALING_H_
