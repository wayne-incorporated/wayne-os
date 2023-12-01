// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_SIGNATURE_SEALING_H_
#define LIBHWSEC_BACKEND_SIGNATURE_SEALING_H_

#include <cstdint>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/status.h"
#include "libhwsec/structures/no_default_init.h"
#include "libhwsec/structures/operation_policy.h"
#include "libhwsec/structures/signature_sealed_data.h"

namespace hwsec {

// SignatureSealing provide the functions to sealing and unsealing with policy
// and signature challenge.
class SignatureSealing {
 public:
  enum class Algorithm {
    kRsassaPkcs1V15Sha1,
    kRsassaPkcs1V15Sha256,
    kRsassaPkcs1V15Sha384,
    kRsassaPkcs1V15Sha512,
  };

  enum class ChallengeID : uint64_t;

  struct ChallengeResult {
    NoDefault<ChallengeID> challenge_id;
    NoDefault<Algorithm> algorithm;
    brillo::Blob challenge;
  };

  // Seals the |unsealed_data| with |policies| and |public_key_spki_der|.
  //
  // |key_algorithms| is the list of signature algorithms supported by the
  // key. Listed in the order of preference (starting from the most
  // preferred); however, the implementation is permitted to ignore this
  // order.
  virtual StatusOr<SignatureSealedData> Seal(
      const std::vector<OperationPolicySetting>& policies,
      const brillo::SecureBlob& unsealed_data,
      const brillo::Blob& public_key_spki_der,
      const std::vector<Algorithm>& key_algorithms) = 0;

  // Creates a challenge from the |sealed_data| with |policy|,
  // |public_key_spki_der|, |key_algorithms|.
  virtual StatusOr<ChallengeResult> Challenge(
      const OperationPolicy& policy,
      const SignatureSealedData& sealed_data,
      const brillo::Blob& public_key_spki_der,
      const std::vector<Algorithm>& key_algorithms) = 0;

  // Unseals the sealed_data from previous |challenge| with the
  // |challenge_response|.
  virtual StatusOr<brillo::SecureBlob> Unseal(
      ChallengeID challenge, const brillo::Blob& challenge_response) = 0;

 protected:
  SignatureSealing() = default;
  ~SignatureSealing() = default;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_SIGNATURE_SEALING_H_
