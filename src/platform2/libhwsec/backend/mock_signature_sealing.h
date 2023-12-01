// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_SIGNATURE_SEALING_H_
#define LIBHWSEC_BACKEND_MOCK_SIGNATURE_SEALING_H_

#include <cstdint>
#include <vector>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/signature_sealing.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/operation_policy.h"
#include "libhwsec/structures/signature_sealed_data.h"

namespace hwsec {

class MockSignatureSealing : public SignatureSealing {
 public:
  MockSignatureSealing() = default;
  explicit MockSignatureSealing(SignatureSealing* on_call) : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, Seal)
        .WillByDefault(Invoke(default_, &SignatureSealing::Seal));
    ON_CALL(*this, Challenge)
        .WillByDefault(Invoke(default_, &SignatureSealing::Challenge));
    ON_CALL(*this, Unseal)
        .WillByDefault(Invoke(default_, &SignatureSealing::Unseal));
  }

  MOCK_METHOD(StatusOr<SignatureSealedData>,
              Seal,
              (const std::vector<OperationPolicySetting>& policies,
               const brillo::SecureBlob& unsealed_data,
               const brillo::Blob& public_key_spki_der,
               const std::vector<Algorithm>& key_algorithms),
              (override));
  MOCK_METHOD(StatusOr<ChallengeResult>,
              Challenge,
              (const OperationPolicy& policy,
               const SignatureSealedData& sealed_data,
               const brillo::Blob& public_key_spki_der,
               const std::vector<Algorithm>& key_algorithms),
              (override));
  MOCK_METHOD(StatusOr<brillo::SecureBlob>,
              Unseal,
              (ChallengeID challenge, const brillo::Blob& challenge_response),
              (override));

 private:
  SignatureSealing* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_SIGNATURE_SEALING_H_
